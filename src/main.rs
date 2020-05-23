use hmac_sha::hmac_sha512;

// TODO: import this from HMAC library instead?
const HASHLEN: usize = 512;

fn flatten_u64(input: &[u64], output: &mut Vec<u8>) {
    for &block in input {
        output.extend_from_slice(&block.to_be_bytes());
    }
    // we should have 8n bytes
    assert_eq!(output.len() % 8, 0);
}

// salt is optional (by spec), but really should always be used
// outputs pseudorandom key - prk
fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8], prk: &mut Vec<u8>) {
    // we are going to get a 512 bit hmac (8 x u64)
    let hmac;

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

    // put all bytes from hmac into prk
    flatten_u64(&hmac, prk);
}

// len is <= 255 * HashLen; prk is usually the input from hkdf_extract()
// outputs key material - okm on length len (in bytes)
fn hkdf_expand(prk: &[u8], info: Option<&[u8]>, len: usize, okm: &mut Vec<u8>) {
    assert!(len <= 255 * HASHLEN);
    let n = (len + HASHLEN - 1) / HASHLEN;

    // collect the source of the key material
    let mut okm_source = Vec::<u64>::new();

    // build okm_source[1]...okm_source[n]
    for i in 1..=n {
        let mut text = vec![];

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

    // flatten to bytes and only put len bytes into okm
    let mut okm_output = Vec::<u8>::new();
    flatten_u64(&okm_source, &mut okm_output);
    okm.extend(okm_output[0..len].iter());
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
