// compact vec to avoid allocation, in most cases
// yeah I know there's already smallvec and tinyvec

use std::{fmt::Display, num::NonZeroU8};

#[derive(Clone, Debug)]
pub enum CVec<T: Copy, const C: usize> {
	Int(([T; C], NonZeroU8)),
	Ext(Vec<T>),
}

impl<T: Copy + Default, const C: usize> CVec<T, C> {
	// since the usage of NonZero, len is internally presented +1
	#[cfg(debug_assertions)]
	const _MAX_CAP: usize = NonZeroU8::MAX.get() as usize - 1;
	#[cfg(debug_assertions)]
	const _MAX_CAP_CHK: () = assert!(C <= Self::_MAX_CAP);
	#[cfg(debug_assertions)]
	const _CVEC63_CHK: () = assert!(std::mem::size_of::<CVec<u8, 63>>() == 64);

	pub fn new() -> Self {
		Self::Int(([T::default(); C], NonZeroU8::new(1).unwrap()))
	}

	pub fn len(&self) -> usize {
		match self {
			CVec::Int((_, l)) => l.get() as usize - 1,
			CVec::Ext(v) => v.len(),
		}
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	pub fn capacity(&self) -> usize {
		match self {
			CVec::Int(_) => C,
			CVec::Ext(v) => v.capacity(),
		}
	}

	// pub fn pop(&mut self) -> Option<T> {
	// 	match self {
	// 		CVec::Int((a, l)) => {
	// 			todo!()
	// 		}
	// 		CVec::Ext(v) => v.pop(),
	// 	}
	// }

	pub fn push(&mut self, t: T) {
		match self {
			Self::Int(a) => {
				let len = a.1.get() as usize - 1;
				if len < C {
					a.0[len] = t;
					a.1 = unsafe { NonZeroU8::new_unchecked(len as u8 + 2) };
				} else {
					let mut v = Vec::with_capacity(len + 1);
					v.extend_from_slice(&a.0[..len]);
					v.push(t);
					*self = Self::Ext(v);
				}
			}
			Self::Ext(v) => v.push(t),
		}
	}
	pub fn extend_from_slice(&mut self, s: &[T]) {
		match self {
			Self::Int(a) => {
				let len = a.1.get() as usize - 1;
				if len + s.len() <= C {
					a.0[len..len + s.len()].copy_from_slice(s);
					a.1 = unsafe { NonZeroU8::new_unchecked((len + s.len()) as u8 + 1) };
				} else {
					let mut v = Vec::with_capacity(len + s.len());
					v.extend_from_slice(&a.0[..len]);
					v.extend_from_slice(s);
					*self = Self::Ext(v);
				}
			}
			Self::Ext(v) => v.extend_from_slice(s),
		}
	}

	fn inner_from_slice(v: &[T]) -> Self {
		#[cfg(debug_assertions)]
		assert!(v.len() <= C);
		let mut a = [T::default(); C];
		a[..v.len()].copy_from_slice(v);
		Self::Int((a, unsafe { NonZeroU8::new_unchecked(v.len() as u8 + 1) }))
	}
}

impl<T: Copy, const C: usize> AsRef<[T]> for CVec<T, C> {
	fn as_ref(&self) -> &[T] {
		match self {
			CVec::Int((a, l)) => &a[..(*l).get() as usize - 1],
			CVec::Ext(v) => v,
		}
	}
}

impl<T: Copy + Default, const C: usize> From<&[T]> for CVec<T, C> {
	fn from(v: &[T]) -> Self {
		if v.len() <= C {
			Self::inner_from_slice(v)
		} else {
			Self::Ext(v.to_vec())
		}
	}
}

impl<T: Copy + Default, const C: usize> From<Vec<T>> for CVec<T, C> {
	fn from(v: Vec<T>) -> Self {
		if v.len() <= C {
			Self::inner_from_slice(&v)
		} else {
			Self::Ext(v)
		}
	}
}

impl<T: Copy + Default, const C: usize> Default for CVec<T, C> {
	fn default() -> Self {
		Self::new()
	}
}

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

impl<T: Hash + Copy, const C: usize> Hash for CVec<T, C> {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.as_ref().hash(state);
	}
}

impl<T: PartialEq + Copy, const C: usize> PartialEq for CVec<T, C> {
	fn eq(&self, other: &Self) -> bool {
		self.as_ref() == other.as_ref()
	}
}

impl<T: Eq + PartialEq + Copy, const C: usize> Eq for CVec<T, C> {}

impl<T: PartialOrd + Copy, const C: usize> PartialOrd for CVec<T, C> {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		self.as_ref().partial_cmp(other.as_ref())
	}
}

impl<T: Ord + Copy, const C: usize> Ord for CVec<T, C> {
	fn cmp(&self, other: &Self) -> Ordering {
		self.as_ref().cmp(other.as_ref())
	}
}

impl<const C: usize> Display for CVec<u8, C> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let b = self.as_ref();
		if let Ok(s) = str::from_utf8(b) {
			write!(f, "{}", s)
		} else {
			todo!()
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{
		fs::File,
		io::{BufRead, BufReader},
		mem::size_of,
		num::NonZeroU8,
	};

	#[test]
	fn cvec_size() {
		println!("Option<u8>: {}", size_of::<Option<u8>>());
		println!("Option<NonZeroU8>: {}", size_of::<Option<NonZeroU8>>());
		println!("Vec<u8>: {}", size_of::<Vec<u8>>());
		println!("Option<Vec<u8>>: {}", size_of::<Option<Vec<u8>>>());

		// compact printing for many const-generic sizes
		macro_rules! print_cvec_sizes {
			($ty:ty; $($n:expr),+ $(,)?) => {
				$(println!(
					concat!("CVec<", stringify!($ty), ", ", stringify!($n), ">: {}"),
					size_of::<CVec<$ty, $n>>()
				);)+
			};
		}

		print_cvec_sizes!(u8; 15, 16, 23, 31, 35, 39, 47, 55, 63);
	}

	#[test]
	fn cvec_push_transitions_to_ext() {
		let mut s: CVec<u8, 3> = CVec::from(&[1u8, 2u8][..]);
		assert_eq!(s.as_ref(), &[1, 2]);
		assert!(matches!(s, CVec::Int(_)));

		s.push(3);
		assert_eq!(s.as_ref(), &[1, 2, 3]);
		assert!(matches!(s, CVec::Int(_)));

		s.push(4);
		assert_eq!(s.as_ref(), &[1, 2, 3, 4]);
		assert!(matches!(s, CVec::Ext(_)));

		s.push(5);
		assert_eq!(s.as_ref(), &[1, 2, 3, 4, 5]);
		assert!(matches!(s, CVec::Ext(_)));
	}

	#[test]
	fn cvec_extend_from_slice_hits_int_and_ext() {
		let mut s: CVec<u8, 4> = CVec::from(&[1u8, 2u8][..]);
		s.extend_from_slice(&[3u8, 4u8]);
		assert_eq!(s.as_ref(), &[1, 2, 3, 4]);
		assert!(matches!(s, CVec::Int(_)));

		s.extend_from_slice(&[5]);
		assert_eq!(s.as_ref(), &[1, 2, 3, 4, 5]);
		assert!(matches!(s, CVec::Ext(_)));

		let mut other: CVec<u8, 3> = CVec::from(&[1u8, 2u8, 3u8, 4u8][..]);
		assert!(matches!(other, CVec::Ext(_)));
		other.extend_from_slice(&[5u8, 6u8]);
		assert_eq!(other.as_ref(), &[1, 2, 3, 4, 5, 6]);
		assert!(matches!(other, CVec::Ext(_)));
	}

	// tough choice
	// === etc/lists/queries-dedupe ===
	// 3517 total names
	//  31,    2198,  62.5%
	//  39,    2716,  77.2%
	//  47,    3130,  89.0%
	//  55,    3353,  95.3%
	//  63,    3485,  99.1%
	// === etc/lists/queries ===
	// 506810 total names
	//  31,  266896,  52.7%
	//  39,  384498,  75.9%
	//  47,  488979,  96.5%
	//  55,  501117,  98.9%
	//  63,  506018,  99.8%
	#[test]
	#[ignore]
	fn query_len_stats() {
		for &(p, t) in &[
			("etc/lists/queries-dedupe", true),
			("etc/lists/queries", false),
		] {
			eprintln!("=== {} ===", p);
			inner_query_len_stats(p, t);
		}
	}

	fn inner_query_len_stats(path: &str, test_cvec: bool) {
		let mut stats = [0; 0x100];
		let mut buf = Vec::with_capacity(0x100);
		let mut r = BufReader::new(File::open(path).unwrap());
		let mut total = 0;
		while r.read_until(b'\n', &mut buf).unwrap() > 0 {
			stats[buf.len()] += 1;
			total += 1;
			if test_cvec {
				const TEST_CVEC_C: usize = 63;
				let a: CVec<u8, TEST_CVEC_C> = CVec::from(buf.as_ref());
				match &a {
					CVec::Int(_) => assert!(buf.len() <= TEST_CVEC_C),
					CVec::Ext(_) => assert!(buf.len() > TEST_CVEC_C),
				}
				assert_eq!(a.as_ref(), &buf);
			}
			buf.clear();
		}
		eprintln!("{} total names", total);
		let mut acc = 0;
		for (i, c) in stats.iter().enumerate() {
			acc += *c;
			// if [15usize, 31, 39, 47, 55, 63].contains(&i) {
			if *c > 0 {
				println!(
					"{:>3}, {:>6}, {:>7}, {:>5.1}%",
					i,
					c,
					acc,
					acc as f32 * 100f32 / total as f32
				)
			}
		}
	}
}
