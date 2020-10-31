//! This module provides a native-Rust generic implementation of the pseudo-random generator based
//! on Postgresql's pseudo_encrypt.
//!
//! The implementation provided maps 1 to 1 wih the orgininal Psql implementation for 32-bit values
//!
//! # Example
//! ```
//! # use pseudo_encrypt::pseudo_encrypt;
//! let input_expected: Vec<(i32, i32)> = vec![
//!     (-10, -1270576520),
//!     (-9, -236348969),
//!     (-8, -1184061109),
//!     (-7, -25446276),
//!     (-6, -1507538963),
//!     (-5, -518858927),
//!     (-4, -1458116927),
//!     (-3, -532482573),
//!     (-2, -157973154),
//!     (-1, -1105881908),
//!     (0, 1777613459),
//!     (1, 561465857),
//!     (2, 436885871),
//!     (3, 576481439),
//!     (4, 483424269),
//!     (5, 1905133426),
//!     (6, 971249312),
//!     (7, 1926833684),
//!     (8, 735327624),
//!     (9, 1731020007),
//!     (10, 792482838),
//! ];
//! for (input, expected) in input_expected {
//!     let r = pseudo_encrypt(input);
//!     assert_eq!(expected, r);
//! }
//! ```
//!
//! Integers represented with more bits are also supported out of the box
//!
//! # Example
//!
//! ```
//! # use pseudo_encrypt::pseudo_encrypt;
//! let r = pseudo_encrypt(u128::MAX);
//! assert_eq!(340282366920938384363736019365210866432, r);
//! ```
//!
//! For more information, see [the Psql documentation for pseudo_encrypt](https://wiki.postgresql.org/wiki/Pseudo_encrypt)
use std::ops::*;

/// Function that acts as a pseudo-random generator of unique values. It produces an integer output
/// that is uniquely associated to its integer input (by a mathematical permutation), but looks
/// random at the same time, with zero collision
///
/// # Example
///
/// ```
/// # use pseudo_encrypt::pseudo_encrypt;
/// let r = pseudo_encrypt(u128::MAX);
/// assert_eq!(340282366920938384363736019365210866432, r);
/// ```
#[inline]
pub fn pseudo_encrypt<A>(a: A) -> A
where
    A: Shl<usize, Output = A>
        + Shr<usize, Output = A>
        + Add<Output = A>
        + Mul<Output = A>
        + Rem<Output = A>
        + BitAnd<Output = A>
        + BitXor<Output = A>
        + PseudoEncryptable
        + From<<A as PseudoEncryptable>::HalfBitType>,
{
    let left_select = (a >> <A as PseudoEncryptable>::HALF_BIT_SIZE)
        & <A as PseudoEncryptable>::HALF_BIT_MAX.into();
    let right_select = a & <A as PseudoEncryptable>::HALF_BIT_MAX.into();
    let (l, r) = (0..3).fold((left_select, right_select), |(l1, r1), _| {
        let l2 = r1;
        let r2 = l1
            ^ (<A as PseudoEncryptable>::cast_from_f32(
                ((<A as PseudoEncryptable>::cast_to_f32(
                    (r1 * <A as PseudoEncryptable>::cast_from_i32(1366)
                        + <A as PseudoEncryptable>::cast_from_i32(150889))
                        % <A as PseudoEncryptable>::cast_from_i32(714025),
                ) / 714025.0)
                    * 32767.0)
                    .round(),
            ));
        (l2, r2)
    });
    (r << <A as PseudoEncryptable>::HALF_BIT_SIZE) + l
}

pub trait PseudoEncryptable: Copy {
    type HalfBitType: Copy;
    const HALF_BIT_SIZE: usize;
    const HALF_BIT_MAX: Self::HalfBitType;

    fn cast_from_i32(f: i32) -> Self;

    fn cast_from_f32(f: f32) -> Self;

    fn cast_to_f32(f: Self) -> f32;
}

impl PseudoEncryptable for i32 {
    type HalfBitType = u16;
    const HALF_BIT_SIZE: usize = 16;
    const HALF_BIT_MAX: Self::HalfBitType = u16::MAX;

    #[inline]
    fn cast_from_i32(f: i32) -> Self {
        f
    }

    #[inline]
    fn cast_from_f32(f: f32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_to_f32(f: Self) -> f32 {
        f as f32
    }
}

impl PseudoEncryptable for i64 {
    type HalfBitType = u32;
    const HALF_BIT_SIZE: usize = 32;
    const HALF_BIT_MAX: Self::HalfBitType = u32::MAX;

    #[inline]
    fn cast_from_i32(f: i32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_from_f32(f: f32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_to_f32(f: Self) -> f32 {
        f as f32
    }
}

impl PseudoEncryptable for i128 {
    type HalfBitType = u64;
    const HALF_BIT_SIZE: usize = 64;
    const HALF_BIT_MAX: Self::HalfBitType = u64::MAX;

    #[inline]
    fn cast_from_i32(f: i32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_from_f32(f: f32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_to_f32(f: Self) -> f32 {
        f as f32
    }
}

impl PseudoEncryptable for u32 {
    type HalfBitType = u16;
    const HALF_BIT_SIZE: usize = 16;
    const HALF_BIT_MAX: Self::HalfBitType = u16::MAX;

    #[inline]
    fn cast_from_i32(f: i32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_from_f32(f: f32) -> Self {
        f as Self
    }
    #[inline]
    fn cast_to_f32(f: Self) -> f32 {
        f as f32
    }
}

impl PseudoEncryptable for u64 {
    type HalfBitType = u32;
    const HALF_BIT_SIZE: usize = 32;
    const HALF_BIT_MAX: Self::HalfBitType = u32::MAX;

    #[inline]
    fn cast_from_i32(f: i32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_from_f32(f: f32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_to_f32(f: Self) -> f32 {
        f as f32
    }
}

impl PseudoEncryptable for u128 {
    type HalfBitType = u64;
    const HALF_BIT_SIZE: usize = 64;
    const HALF_BIT_MAX: Self::HalfBitType = u64::MAX;

    #[inline]
    fn cast_from_i32(f: i32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_from_f32(f: f32) -> Self {
        f as Self
    }

    #[inline]
    fn cast_to_f32(f: Self) -> f32 {
        f as f32
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    const TEST_CASES: u32 = 1000000;

    #[test]
    fn test_test_pseudo_encrypt_values_u32() {
        let input_expected = vec![
            (0, 1777613459),
            (1, 561465857),
            (2, 436885871),
            (3, 576481439),
            (4, 483424269),
            (5, 1905133426),
            (6, 971249312),
            (7, 1926833684),
            (8, 735327624),
            (9, 1731020007),
            (10, 792482838),
        ];
        for (input, expected) in input_expected {
            let r = pseudo_encrypt(input);
            assert_eq!(expected, r);
        }
    }

    #[test]
    fn test_test_pseudo_encrypt_values_i32() {
        let input_expected: Vec<(i32, i32)> = vec![
            (-10, -1270576520),
            (-9, -236348969),
            (-8, -1184061109),
            (-7, -25446276),
            (-6, -1507538963),
            (-5, -518858927),
            (-4, -1458116927),
            (-3, -532482573),
            (-2, -157973154),
            (-1, -1105881908),
            (0, 1777613459),
            (1, 561465857),
            (2, 436885871),
            (3, 576481439),
            (4, 483424269),
            (5, 1905133426),
            (6, 971249312),
            (7, 1926833684),
            (8, 735327624),
            (9, 1731020007),
            (10, 792482838),
        ];
        for (input, expected) in input_expected {
            let r = pseudo_encrypt(input);
            assert_eq!(expected, r);
        }
    }

    #[test]
    fn test_test_pseudo_encrypt_no_collisions_u32() {
        let seen_inputs_mutex = Mutex::new(HashSet::with_capacity(TEST_CASES as usize));
        let seen_results_mutex = Mutex::new(HashMap::with_capacity(TEST_CASES as usize));
        proptest!(ProptestConfig::with_cases(TEST_CASES), move |(u: u32)| {
            let mut seen_inputs = seen_inputs_mutex.lock().unwrap();
            prop_assume!(!seen_inputs.contains(&u));
            seen_inputs.insert(u);

            let mut seen_results = seen_results_mutex.lock().unwrap();
            let r = pseudo_encrypt(u);

            let previous_input_for_result = seen_results.get(&r);
            prop_assert!(previous_input_for_result.is_none(), "Previous input [{:?}] yielded the same result [{}]", previous_input_for_result, r);
            seen_results.insert(r, u);
        });
    }

    #[test]
    fn test_test_pseudo_encrypt_no_collisions_i32() {
        let seen_inputs_mutex = Mutex::new(HashSet::with_capacity(TEST_CASES as usize));
        let seen_results_mutex = Mutex::new(HashMap::with_capacity(TEST_CASES as usize));
        proptest!(ProptestConfig::with_cases(TEST_CASES), move |(u: i32)| {
            let mut seen_inputs = seen_inputs_mutex.lock().unwrap();
            prop_assume!(!seen_inputs.contains(&u));

            seen_inputs.insert(u);

            let mut seen_results = seen_results_mutex.lock().unwrap();
            let r = pseudo_encrypt(u);

            let previous_input_for_result = seen_results.get(&r);
            prop_assert!(previous_input_for_result.is_none(), "Previous input [{:?}] yielded the same result [{}]", previous_input_for_result, r);
            seen_results.insert(r, u);
        });
    }

    #[test]
    fn test_test_pseudo_encrypt_no_collisions_i64() {
        let seen_inputs_mutex = Mutex::new(HashSet::with_capacity(TEST_CASES as usize));
        let seen_results_mutex = Mutex::new(HashMap::with_capacity(TEST_CASES as usize));
        proptest!(ProptestConfig::with_cases(TEST_CASES), move |(u: i64)| {
            let mut seen_inputs = seen_inputs_mutex.lock().unwrap();
            prop_assume!(!seen_inputs.contains(&u));
            seen_inputs.insert(u);

            let mut seen_results = seen_results_mutex.lock().unwrap();
            let r = pseudo_encrypt(u);

            let previous_input_for_result = seen_results.get(&r);
            prop_assert!(previous_input_for_result.is_none(), "Previous input [{:?}] yielded the same result [{}]", previous_input_for_result, r);
            seen_results.insert(r, u);
        });
    }

    #[test]
    fn test_test_pseudo_encrypt_no_collisions_u64() {
        let seen_inputs_mutex = Mutex::new(HashSet::with_capacity(TEST_CASES as usize));
        let seen_results_mutex = Mutex::new(HashMap::with_capacity(TEST_CASES as usize));
        proptest!(ProptestConfig::with_cases(TEST_CASES), move |(u: u64)| {
            let mut seen_inputs = seen_inputs_mutex.lock().unwrap();
            prop_assume!(!seen_inputs.contains(&u));
            seen_inputs.insert(u);

            let mut seen_results = seen_results_mutex.lock().unwrap();
            let r = pseudo_encrypt(u);

            let previous_input_for_result = seen_results.get(&r);
            prop_assert!(previous_input_for_result.is_none(), "Previous input [{:?}] yielded the same result [{}]", previous_input_for_result, r);
            seen_results.insert(r, u);
        });
    }

    #[test]
    fn test_test_pseudo_encrypt_no_collisions_i128() {
        let seen_inputs_mutex = Mutex::new(HashSet::with_capacity(TEST_CASES as usize));
        let seen_results_mutex = Mutex::new(HashMap::with_capacity(TEST_CASES as usize));
        proptest!(ProptestConfig::with_cases(TEST_CASES), move |(u: i128)| {
            let mut seen_inputs = seen_inputs_mutex.lock().unwrap();
            prop_assume!(!seen_inputs.contains(&u));
            seen_inputs.insert(u);

            let mut seen_results = seen_results_mutex.lock().unwrap();
            let r = pseudo_encrypt(u);

            let previous_input_for_result = seen_results.get(&r);
            prop_assert!(previous_input_for_result.is_none(), "Previous input [{:?}] yielded the same result [{}]", previous_input_for_result, r);
            seen_results.insert(r, u);
        });
    }

    #[test]
    fn test_test_pseudo_encrypt_no_collisions_u128() {
        let seen_inputs_mutex = Mutex::new(HashSet::with_capacity(TEST_CASES as usize));
        let seen_results_mutex = Mutex::new(HashMap::with_capacity(TEST_CASES as usize));
        proptest!(ProptestConfig::with_cases(TEST_CASES), move |(u: u128)| {
            let mut seen_inputs = seen_inputs_mutex.lock().unwrap();
            prop_assume!(!seen_inputs.contains(&u));
            seen_inputs.insert(u);

            let mut seen_results = seen_results_mutex.lock().unwrap();
            let r = pseudo_encrypt(u);

            let previous_input_for_result = seen_results.get(&r);
            prop_assert!(previous_input_for_result.is_none(), "Previous input [{:?}] yielded the same result [{}]", previous_input_for_result, r);
            seen_results.insert(r, u);
        });
    }
}
