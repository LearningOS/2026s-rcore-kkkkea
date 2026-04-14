//! Process management syscalls

use alloc::sync::Arc;

use crate::{
    loader::get_app_data_by_name,
    mm::{
        remain_page_num, translated_byte_buffer, translated_refmut, translated_str, MapPermission,
        VirtAddr,
    },
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskControlBlock,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    let ptr = _ts as *mut u8;
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    let current_satp = current_task().unwrap().get_user_token();
    let byte_buffer_mut =
        translated_byte_buffer(current_satp, ptr, core::mem::size_of::<TimeVal>());

    let mut local_ptr = (&time_val) as *const TimeVal as *const u8;
    for buffer in byte_buffer_mut {
        let buffer_size = buffer.len();
        unsafe {
            core::ptr::copy_nonoverlapping(local_ptr, buffer.as_mut_ptr(), buffer_size);
            local_ptr = local_ptr.add(buffer_size);
        }
    }

    0
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    let start_va: VirtAddr = _start.into();
    let end_va: VirtAddr = (_start + _len).into();

    if !start_va.aligned() || _port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }

    let require_page_num = end_va.ceil().0 - start_va.floor().0;
    if require_page_num > remain_page_num() {
        -1
    } else {
        current_task()
            .unwrap()
            .inner_exclusive_access()
            .memory_set
            .insert_framed_area_checked(
                start_va,
                end_va,
                MapPermission::from_bits(((_port & 0xff) << 1) as u8).unwrap() | MapPermission::U,
            )
    }
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    let start_va: VirtAddr = _start.into();

    if !start_va.aligned() {
        return -1;
    }

    current_task()
        .unwrap()
        .inner_exclusive_access()
        .memory_set
        .remove_area_with_start_vpn_checked(_start.into(), (_start + _len).into())
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);

    let token = current_user_token();
    let path = translated_str(token, _path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        let new_task = Arc::new(TaskControlBlock::new(data));
        let mut new_inner = new_task.inner_exclusive_access();
        new_inner.parent = Some(Arc::downgrade(&task));
        drop(new_inner);

        let mut current_inner = task.inner_exclusive_access();
        current_inner.children.push(Arc::clone(&new_task));

        let new_pid = new_task.pid.0 as isize;
        add_task(new_task);
        new_pid
    } else {
        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );
    if _prio >= 2 {
        current_task().unwrap().inner_exclusive_access().priority = _prio as u16;
        _prio
    } else {
        -1
    }
}
