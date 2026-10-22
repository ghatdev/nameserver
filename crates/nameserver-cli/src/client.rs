use anyhow::{Context, Result};

/// HTTP client for the nameserver control plane API.
pub struct Client {
    http: reqwest::Client,
    base_url: String,
}

impl Client {
    pub fn new(base_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .context("failed to build HTTP client")?;
        // Strip trailing slash for consistent URL joining.
        let base_url = base_url.trim_end_matches('/').to_string();
        Ok(Self { http, base_url })
    }

    /// Send a GET request and return the response body as a JSON value.
    pub async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("GET {url} returned HTTP {status}: {body}");
        }
        serde_json::from_str(&body).with_context(|| format!("failed to parse JSON from GET {url}"))
    }

    /// Send a GET request and return the response body as plain text.
    pub async fn get_text(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("GET {url} returned HTTP {status}: {body}");
        }
        Ok(body)
    }

    /// Send a PUT request with a JSON body and return the response as JSON.
    pub async fn put_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .put(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("PUT {url} returned HTTP {status}: {text}");
        }
        serde_json::from_str(&text).with_context(|| format!("failed to parse JSON from PUT {url}"))
    }

    /// Send a POST request with a JSON body and return the response as JSON.
    pub async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("POST {url} returned HTTP {status}: {text}");
        }
        serde_json::from_str(&text).with_context(|| format!("failed to parse JSON from POST {url}"))
    }

    /// Send a POST request with a JSON body and return the response as raw bytes.
    pub async fn post_bytes_json(&self, path: &str, body: &serde_json::Value) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            anyhow::bail!("POST {url} returned HTTP {status}: {text}");
        }
        Ok(resp.bytes().await?.to_vec())
    }

    /// Send a POST request with raw bytes and return the response as text.
    pub async fn post_bytes(&self, path: &str, bytes: Vec<u8>, checksum: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("x-checksum", checksum)
            .header("content-type", "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("POST {url} returned HTTP {status}: {body}");
        }
        Ok(body)
    }

    /// Send a POST request with a plain text body and return the response as JSON.
    pub async fn post_text(&self, path: &str, text: String) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("content-type", "text/plain; charset=utf-8")
            .body(text)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("POST {url} returned HTTP {status}: {body}");
        }
        serde_json::from_str(&body).with_context(|| format!("failed to parse JSON from POST {url}"))
    }

    /// Send a POST with no body and return the response as JSON.
    pub async fn post_empty(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("POST {url} returned HTTP {status}: {text}");
        }
        serde_json::from_str(&text).with_context(|| format!("failed to parse JSON from POST {url}"))
    }

    /// Send a GET request and return the response body as raw bytes.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await?;
            anyhow::bail!("GET {url} returned HTTP {status}: {body}");
        }
        Ok(resp.bytes().await?.to_vec())
    }

    /// Send a DELETE request and return the response as JSON.
    pub async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .delete(&url)
            .send()
            .await
            .with_context(|| format!("DELETE {url}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("DELETE {url} returned HTTP {status}: {text}");
        }
        serde_json::from_str(&text)
            .with_context(|| format!("failed to parse JSON from DELETE {url}"))
    }
}

/// Compute SHA-256 hex digest of raw bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256Soft::new();
    hasher.update(data);
    hasher.finalize_hex()
}

/// Minimal software SHA-256 (avoids adding sha2 crate dependency).
/// Uses the standard FIPS 180-4 algorithm.
struct Sha256Soft {
    state: [u32; 8],
    buf: Vec<u8>,
    total_len: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256Soft {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: Vec::new(),
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.total_len += data.len() as u64;

        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().expect("64 bytes");
            self.compress(&block);
            self.buf.drain(..64);
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_len * 8;
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(&bit_len.to_be_bytes());

        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().expect("64 bytes");
            self.compress(&block);
            self.buf.drain(..64);
        }

        use std::fmt::Write;
        let mut hex = String::with_capacity(64);
        for word in &self.state {
            write!(hex, "{word:08x}").expect("write to string");
        }
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
