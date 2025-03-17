use core::{cell::RefCell, sync::atomic::AtomicBool};

// pub struct LazyLock<T> {
//     lock: AtomicBool,
//     init: fn() -> T,
//     val: Option<RefCell<T>>,
// }

// impl<T> LazyLock<T> {
//     pub fn new(init: fn() -> T) -> Self {
//         LazyLock {
//             lock: AtomicBool::new(false),
//             init,
//             val: None,
//         }
//     }

//     pub fn get(&mut self) -> &T {
//         if let ok = self.lock.get_mut() {
//             if *ok {
//                 self.val = Some(RefCell::new((self.init)()));

//             }
//         }
//         if let Some(ref val) = self.val {
//             return &val.borrow();
//         }
//         panic!("LazyLock not initialized");
//     }

//     pub fn get_mut(&mut self) -> &mut T {
//         if let ok = self.lock.get_mut() {
//             if ok {
//                 self.val = Some((self.init)());
//             }
//         }
//         &mut self.val.unwrap()
//     }
// }

pub struct Mutex<T> {
    pub lock: AtomicBool,
    pub val: T,
}

pub struct Guard<'a, T> {
    mutex: &'a mut Mutex<T>,
}

impl<'a, T> Guard<'a, T> {
    pub fn get(&self) -> &T {
        &self.mutex.val
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.mutex.val
    }
}

impl<'a, T> Drop for Guard<'a, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

unsafe impl<T> Send for Mutex<T> {}
unsafe impl<T> Sync for Mutex<T> {}
impl<'a, T> Mutex<T> {
    pub const fn new(val: T) -> Self {
        Mutex {
            lock: AtomicBool::new(false),
            val,
        }
    }

    pub fn lock(&'a mut self) -> Guard<'a, T> {
        loop {
            let mut lk = self.lock.get_mut();
            if !*lk {
                *lk = true;
                break;
            }
            core::hint::spin_loop();
        }
        Guard { mutex: self }
    }

    fn unlock(&mut self) {
        let mut lk = self.lock.get_mut();
        *lk = false;
    }
}

impl<T> Drop for Mutex<T> {
    fn drop(&mut self) {
        self.unlock();
    }
}
