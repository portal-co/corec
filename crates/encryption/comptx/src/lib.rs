#![no_std]

use core::iter::{self, once};

use base64::Engine;
pub fn compress(data: &[u8], on_chunk: &mut (dyn FnMut(&mut (dyn Iterator<Item = u8>)) + '_)){
    for chunk in data.split(|a|*a == b'\n'){
        on_chunk(&mut core::iter::once((chunk.len() as u64).to_le_bytes()).flatten());
        if chunk.iter().all(|x|(*x as char).is_ascii_alphanumeric()){
            on_chunk(&mut once(0).chain(chunk.chunks(4).flat_map(|a|{
                let mut b = [0u8;3];
                let x = base64::engine::general_purpose::STANDARD.decode_slice(a, &mut b).unwrap();
                b.into_iter().take(x)
            })))
        }else{
            on_chunk(&mut once(1).chain(chunk.iter().cloned()));
        }
    }
}
pub fn decompress(mut data: impl Iterator<Item = u8>) -> impl Iterator<Item = u8>{
    enum State{
        Len,
        Mode(u64),
        Data(u64, u8),
    }
    let mut state = State::Len;
    iter::from_fn(move||loop{
        match state{
            State::Len=>{
                let mut buf = [0u8;8];
                for b in buf.iter_mut(){
                    *b = data.next()?;
                }
                let len = u64::from_le_bytes(buf);
                state = State::Mode(len);
            }
            State::Mode(len)=>{
                let mode = data.next()?;
                state = State::Data(len, mode);
            }
            State::Data(0,_)=>{
                state = State::Len;
                return Some([b'\n';4].into_iter().take(1));
            }
            State::Data(len, mode)=>{
                let byte = match mode{
                    0=>{
                        let mut buf = [0u8;3];
                        for b in buf.iter_mut(){
                            *b = data.next()?;
                        }
                        let mut out = [0u8;4];
                        let x = base64::engine::general_purpose::STANDARD.encode_slice(&buf, &mut out).unwrap();
                        state = State::Data(len - (x as u64), mode);
                        out.into_iter().take(x)
                    }
                    1=>{
                        state = State::Data(len - 1, mode);
                        let x = [data.next()?;4];
                        x.into_iter().take(1)
                    },
                    _=>panic!("invalid mode"),
                };
                return Some(byte);
            }
        }
    }).flatten()
}