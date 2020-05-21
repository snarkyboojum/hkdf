use hmac_sha::hmac_sha512;

// TODO: import this from HMAC library instead?
const HASHLEN: usize = 512;

// salt is optional (by spec), but really should always be used
// outputs pseudorandom key - prk
fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8], prk: &mut [u8]) {
    // we are going to get a 512 bit hmac
    let mut hmac = [0u64; 8];

    match salt {
        None => {
            // if no salt is provided use a HashLen of 0s
            let empty_salt = [0u8; 64];
            hmac = hmac_sha512(ikm, &empty_salt);
        }
        Some(s) => {
            hmac = hmac_sha512(ikm, s);
        }
    }

    // TODO: convert hmac to prk (array of bytes)
    // ...
    // prk = hmac
}

// len is <= 255 * HashLen; prk is usually the input from hkdf_extract()
// outputs key material - okm on length len (in bytes)
fn hkdf_expand(prk: &[u8], info: Option<&[u8]>, len: usize, okm: &mut [u8]) {
    assert!(len <= 255 * HASHLEN);
    let n = (len + HASHLEN - 1) / HASHLEN;

    // collect the source of the key material
    let mut okm_source = Vec::<u64>::new();

    // build okm_source[1]...okm_source[n]
    for i in 1..=n {
        let mut text = vec![];

        /*
        if okm_source.len() != 0 {
            text.extend_from_slice(&okm_source[i - 1]);
        }
        */
        // info is optional, and it could also be empty
        if let Some(context) = info {
            text.extend_from_slice(context);
        }
        // append a single byte representing the count
        text.extend_from_slice(&[i as u8]);

        let hmac = hmac_sha512(prk, &text);
        okm_source.extend_from_slice(&hmac);
    }

    // TODO: do proper error checking here
    assert!(okm_source.len() * 8 >= len);
    // okm = okm_source[0..len];
}

fn main() {
    println!("Welcome to HKDF, an HMAC key derivation function implementation written in Rust!");
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hkdf_extract() {}
}
