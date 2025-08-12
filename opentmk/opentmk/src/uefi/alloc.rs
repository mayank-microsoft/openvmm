use core::alloc::GlobalAlloc;
use core::cell::RefCell;

use linked_list_allocator::LockedHeap;
use sync_nostd::Mutex;
use uefi::allocator::Allocator;
use uefi::boot::AllocateType;
use uefi::boot::MemoryType;
use uefi::boot::{self};

pub const SIZE_1MB: usize = 1024 * 1024;
const PAGE_SIZE: usize = 4096;

#[global_allocator]
pub static ALLOCATOR: MemoryAllocator = MemoryAllocator {
    use_locked_heap: Mutex::new(RefCell::new(false)),
    locked_heap: LockedHeap::empty(),
    uefi_allocator: Allocator {},
};

pub struct MemoryAllocator {
    use_locked_heap: Mutex<RefCell<bool>>,
    locked_heap: LockedHeap,
    uefi_allocator: Allocator,
}

#[expect(unsafe_code)]
unsafe impl GlobalAlloc for MemoryAllocator {
    #[allow(unsafe_code)]
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if *self.use_locked_heap.lock().borrow() {
            unsafe { self.locked_heap.alloc(layout) }
        } else {
            unsafe { self.uefi_allocator.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        if *self.use_locked_heap.lock().borrow() {
            unsafe { self.locked_heap.dealloc(ptr, layout) }
        } else {
            unsafe { self.uefi_allocator.dealloc(ptr, layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
        if *self.use_locked_heap.lock().borrow() {
            unsafe { self.locked_heap.alloc_zeroed(layout) }
        } else {
            unsafe { self.uefi_allocator.alloc_zeroed(layout) }
        }
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        if *self.use_locked_heap.lock().borrow() {
            unsafe { self.locked_heap.realloc(ptr, layout, new_size) }
        } else {
            unsafe { self.uefi_allocator.realloc(ptr, layout, new_size) }
        }
    }
}

impl MemoryAllocator {
    pub fn init(&self, size: usize) -> bool {
        let pages = ((SIZE_1MB * size) / 4096) + 1;
        let size = pages * 4096;
        let mem: Result<core::ptr::NonNull<u8>, uefi::Error> = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::BOOT_SERVICES_DATA,
            pages,
        );
        if mem.is_err() {
            return false;
        }
        let ptr = mem.unwrap().as_ptr();
        unsafe {
            self.locked_heap.lock().init(ptr, size);
        }
        *self.use_locked_heap.lock().borrow_mut() = true;
        true
    }

    #[allow(dead_code)]
    pub fn get_page_alligned_memory(&self, size: usize) -> *mut u8 {
        let pages = ((SIZE_1MB * size) / PAGE_SIZE) + 1;
        let mem: Result<core::ptr::NonNull<u8>, uefi::Error> = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::BOOT_SERVICES_DATA,
            pages,
        );
        if mem.is_err() {
            return core::ptr::null_mut();
        }
        mem.unwrap().as_ptr()
    }
}
