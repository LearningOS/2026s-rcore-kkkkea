//! Types related to task management
use super::TaskContext;
use crate::config::{MAX_SYSCALL_NUM, TRAP_CONTEXT_BASE};
use crate::mm::{
    kernel_stack_position, MapPermission, MemorySet, PhysPageNum, VirtAddr, KERNEL_SPACE,
};
use crate::syscall::syscall_id_to_order;
use crate::trap::{trap_handler, TrapContext};
use alloc::vec::Vec;

/// The task control block (TCB) of a task.
pub struct TaskControlBlock {
    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,

    /// Application address space
    pub memory_set: MemorySet,

    /// The phys page number of trap context
    pub trap_cx_ppn: PhysPageNum,

    /// The size(top addr) of program which is loaded from elf file
    pub base_size: usize,

    /// Heap bottom
    pub heap_bottom: usize,

    /// Program break
    pub program_brk: usize,

    /// sycall record
    syscall_record: SyscallRecord,
}

impl TaskControlBlock {
    /// get the trap context
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }

    /// get the user token
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }

    /// map user space
    pub fn map_user_space(
        &mut self,
        va_start: VirtAddr,
        va_end: VirtAddr,
        map_perm: MapPermission,
    ) -> isize {
        self.memory_set.map_user_space(va_start, va_end, map_perm)
    }

    /// unmap user space
    pub fn unmap_user_space(&mut self, va_start: VirtAddr, va_end: VirtAddr) -> isize {
        self.memory_set.unmap_user_space(va_start, va_end)
    }

    /// Based on the elf info in program, build the contents of task in a new address space
    pub fn new(elf_data: &[u8], app_id: usize) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        let task_status = TaskStatus::Ready;
        // map a kernel-stack in kernel space
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(app_id);
        KERNEL_SPACE.exclusive_access().insert_framed_area(
            kernel_stack_bottom.into(),
            kernel_stack_top.into(),
            MapPermission::R | MapPermission::W,
        );
        let task_control_block = Self {
            task_status,
            task_cx: TaskContext::goto_trap_return(kernel_stack_top),
            memory_set,
            trap_cx_ppn,
            base_size: user_sp,
            heap_bottom: user_sp,
            program_brk: user_sp,
            syscall_record: SyscallRecord::new(),
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
    /// change the location of the program break. return None if failed.
    pub fn change_program_brk(&mut self, size: i32) -> Option<usize> {
        let old_break = self.program_brk;
        let new_brk = self.program_brk as isize + size as isize;
        if new_brk < self.heap_bottom as isize {
            return None;
        }
        let result = if size < 0 {
            self.memory_set
                .shrink_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        } else {
            self.memory_set
                .append_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        };
        if result {
            self.program_brk = new_brk as usize;
            Some(old_break)
        } else {
            None
        }
    }

    /// update record
    pub fn update_record(&mut self, syscall_id: usize) {
        self.syscall_record.update(syscall_id);
    }

    /// get record
    pub fn get_record(&self, syscall_id: usize) -> usize {
        self.syscall_record.get_record(syscall_id)
    }
}

#[derive(Copy, Clone, PartialEq)]
/// task status: UnInit, Ready, Running, Exited
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}

struct SyscallRecord {
    record: Vec<usize>,
}

impl SyscallRecord {
    fn new() -> Self {
        let mut record = Vec::with_capacity(MAX_SYSCALL_NUM + 1);
        record.resize(MAX_SYSCALL_NUM + 1, 0);
        Self { record }
    }

    pub fn update(&mut self, syscall_id: usize) {
        let index = syscall_id_to_order(syscall_id);
        self.record[index] += 1;
    }

    pub fn get_record(&self, syscall_id: usize) -> usize {
        self.record[syscall_id_to_order(syscall_id)]
    }
}
