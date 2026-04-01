//! Process management syscalls

use crate::{
    config::{PAGE_SIZE, PAGE_SIZE_BITS},
    mm::{remain_ppn, MapPermission, PageTable, PhysAddr, VirtAddr, VirtPageNum},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, get_current_record,
        map_user_space_for_current, suspend_current_and_run_next, unmap_user_space_for_current,
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
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let current_satp = current_user_token();
    let page_table = PageTable::from_token(current_satp);

    let dest_va = VirtAddr::from(_ts as usize);
    let offset = dest_va.page_offset();

    if offset < PAGE_SIZE - 16 {
        let dest_vpn = dest_va.floor();
        let dest_ppn = page_table.translate(dest_vpn).unwrap().ppn();
        let dest_pa = PhysAddr::from((dest_ppn.0 << PAGE_SIZE_BITS) + offset);
        *(dest_pa.get_mut::<TimeVal>()) = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        }
    } else {
        let vpn1 = dest_va.floor();
        let vpn2 = VirtPageNum(vpn1.0 + 1);

        let ppn1 = page_table.translate(vpn1).unwrap().ppn();
        let ppn2 = page_table.translate(vpn2).unwrap().ppn();

        let dest1 = ((ppn1.0 << PAGE_SIZE_BITS) + offset) as *mut usize;
        let dest2 = (ppn2.0 << PAGE_SIZE_BITS) as *mut usize;

        unsafe {
            *dest1 = us / 1_000_000;
            *dest2 = us % 1_000_000;
        }
    }

    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(_trace_request: usize, _id: usize, _data: usize) -> isize {
    trace!("kernel: sys_trace");

    match _trace_request {
        0 | 1 => {
            if !VirtAddr::vaild_addr(_id) {
                return -1;
            }

            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id);
            let page_offset = va.page_offset();
            let vpn = va.floor();
            let pte = page_table.translate(vpn);
            if pte.is_none() {
                return -1;
            }
            let pte = pte.unwrap();
            if !pte.is_valid() {
                return -1;
            }

            let dst_ptr = ((pte.ppn().0 << PAGE_SIZE_BITS) + page_offset) as *mut u8;

            if _trace_request == 0 {
                if !pte.readable() {
                    return -1;
                }
                unsafe { dst_ptr.read() as isize }
            } else {
                if !pte.writable() {
                    return -1;
                }
                unsafe {
                    dst_ptr.write((_data & 0xff) as u8);
                }
                0
            }
        }
        2 => get_current_record(_id) as isize,
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(_start + _len);

    if !start_va.aligned() || _port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }

    let needed_ppn = (_len - 1 + PAGE_SIZE) / PAGE_SIZE;
    if needed_ppn > remain_ppn() {
        return -1;
    }

    map_user_space_for_current(
        start_va,
        end_va,
        MapPermission::from_bits(((_port & 0xff) << 1) as u8).unwrap(),
    )
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    let va_start = VirtAddr::from(_start);
    let va_end = VirtAddr::from(_start + _len);

    if !va_start.aligned() {
        return -1;
    }

    unmap_user_space_for_current(va_start, va_end)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
