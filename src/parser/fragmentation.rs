use nom::bits::bits;
use nom::bits::complete::take;
use nom::combinator::map;
use nom::error::ErrorKind;
use nom::IResult;
use nom::sequence::tuple;
use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;
use ux::u13;

#[derive(Debug, Clone)]
pub(crate) struct FragmentInfo {
    more_fragments: bool,
    offset: u13,
}

impl Serialize for FragmentInfo {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let mut state = serializer.serialize_struct("FragmentInfo", 2)?;
        state.serialize_field("more_fragments", &self.more_fragments)?;
        let offset: u16 = self.offset.into();
        state.serialize_field("offset", &offset)?;
        state.end()
    }
}

#[derive(Serialize, Debug, Clone)]
pub(crate) enum Fragmentation {
    NoFragmentation,
    Fragmented(FragmentInfo),
}

impl Into<u16> for Fragmentation {
    fn into(self) -> u16 {
        let mut result = 0;
        match self {
            Fragmentation::NoFragmentation => {
                result |= 1 << 14;
            }
            Fragmentation::Fragmented(info) => {
                result |= (info.more_fragments as u16) << 13;
                result |= u16::from(info.offset);
            }
        }
        result
    }
}

pub(crate) fn fragmentation(input: &[u8]) -> IResult<&[u8], Fragmentation> {
    map(bits::<_, (u8, u8, u8, u16), ((&[u8], usize), ErrorKind), _, _>(tuple((
        take(1usize),
        take(1usize),
        take(1usize),
        take(13usize),
    ))), |(_reserved, not_fragment, more_fragment, fragment_offset)| {
        if not_fragment == 1 {
            Fragmentation::NoFragmentation
        } else {
            Fragmentation::Fragmented(FragmentInfo {
                more_fragments: more_fragment == 1,
                offset: u13::new(fragment_offset),
            })
        }
    })(input)
}