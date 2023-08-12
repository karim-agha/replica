use {dusk_bls12_381_sign::APK, dusk_bytes::Serializable};

pub trait ToBs58 {
	fn to_bs58(&self) -> String;
}

impl ToBs58 for APK {
	fn to_bs58(&self) -> String {
		bs58::encode(self.to_bytes()).into_string()
	}
}

impl<const N: usize> ToBs58 for [u8; N] {
	fn to_bs58(&self) -> String {
		bs58::encode(self).into_string()
	}
}
