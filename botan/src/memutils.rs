
use botan_sys::*;
use std::mem;
use std::os::raw::c_void;

pub fn const_time_compare<T: Copy>(a: &[T], b: &[T]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let bytes = mem::size_of::<T>() * a.len();
    let rc = unsafe { botan_constant_time_compare(a.as_ptr() as *const u8, b.as_ptr() as *const u8, bytes) };

    return rc == 0;
}

pub fn scrub_mem<T: Copy>(a: &mut [T]) {
    let bytes = mem::size_of::<T>() * a.len();
    unsafe { botan_scrub_mem(a.as_mut_ptr() as *mut c_void, bytes) };
}

