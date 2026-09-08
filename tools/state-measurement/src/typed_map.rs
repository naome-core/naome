//! Isolated in-memory byte-map calibration for the selected V1 hash construction.
//! Namespace tags and opaque records are corpus inputs, not a canonical schema.
//! No disk format, authenticated acquisition, state authority, or work limit.
use crate::numbers::encode_length_be;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::sync::Arc;

type Hash = [u8; 32];
const KEY: &[u8] = b"naome/consensus/v1/map-key\0";
const EMPTY: &[u8] = b"naome/consensus/v1/map-empty\0";
const LEAF: &[u8] = b"naome/consensus/v1/map-leaf\0";
const BRANCH: &[u8] = b"naome/consensus/v1/map-branch\0";

#[derive(Clone)]
struct Map {
    tag: Arc<[u8]>,
    root: Option<Arc<Node>>,
}
struct Node {
    hash: Hash,
    body: Body,
}
enum Body {
    Leaf {
        route: Hash,
        key: Arc<[u8]>,
        value: Arc<[u8]>,
    },
    Branch {
        bit: u8,
        left: Arc<Node>,
        right: Arc<Node>,
    },
}
#[derive(Debug, PartialEq, Eq)]
struct Collision;

fn digest(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = encode_length_be(&BigUint::from(value.len()));
    out.extend_from_slice(value);
    out
}
fn side(route: &Hash, bit: u8) -> bool {
    route[usize::from(bit / 8)] & (0x80 >> (bit % 8)) != 0
}
fn split(a: &Hash, b: &Hash) -> Option<u8> {
    a.iter().zip(b).enumerate().find_map(|(i, (a, b))| {
        let x = a ^ b;
        (x != 0).then(|| u8::try_from(i * 8 + x.leading_zeros() as usize).unwrap())
    })
}
impl Map {
    fn new(tag: BigUint) -> Self {
        Self {
            tag: encode_length_be(&tag).into(),
            root: None,
        }
    }
    fn root_hash(&self) -> Hash {
        self.root
            .as_ref()
            .map_or_else(|| digest(&[EMPTY, &self.tag]), |n| n.hash)
    }
    fn route(&self, key: &[u8]) -> Hash {
        digest(&[KEY, &self.tag, &bytes(key)])
    }
    fn leaf(&self, route: Hash, key: Vec<u8>, value: Vec<u8>) -> Arc<Node> {
        Arc::new(Node {
            hash: digest(&[LEAF, &self.tag, &bytes(&key), &bytes(&value)]),
            body: Body::Leaf {
                route,
                key: key.into(),
                value: value.into(),
            },
        })
    }
    fn branch(&self, bit: u8, left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
        Arc::new(Node {
            hash: digest(&[BRANCH, &self.tag, &[bit], &left.hash, &right.hash]),
            body: Body::Branch { bit, left, right },
        })
    }
    fn terminal<'a>(&self, mut node: &'a Arc<Node>, route: &Hash) -> &'a Arc<Node> {
        while let Body::Branch { bit, left, right } = &node.body {
            node = if side(route, *bit) { right } else { left };
        }
        node
    }
    fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, Collision> {
        let Some(root) = &self.root else {
            return Ok(None);
        };
        let route = self.route(key);
        let Body::Leaf {
            route: stored_route,
            key: stored,
            value,
        } = &self.terminal(root, &route).body
        else {
            unreachable!()
        };
        if stored.as_ref() == key {
            Ok(Some(value))
        } else if *stored_route == route {
            Err(Collision)
        } else {
            Ok(None)
        }
    }
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Collision> {
        let route = self.route(&key);
        self.insert_routed(route, key, value)
    }
    // The public-to-this-module path always computes real SHA-256. Tests can
    // inject a route here solely to exercise otherwise infeasible collisions.
    fn insert_routed(
        &mut self,
        route: Hash,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), Collision> {
        let Some(root) = &self.root else {
            self.root = Some(self.leaf(route, key, value));
            return Ok(());
        };
        let Body::Leaf {
            route: old_route,
            key: old_key,
            ..
        } = &self.terminal(root, &route).body
        else {
            unreachable!()
        };
        let bit = split(&route, old_route);
        if bit.is_none() && old_key.as_ref() != key {
            return Err(Collision);
        }
        let leaf = self.leaf(route, key, value);
        self.root = Some(self.put(root, &route, bit, &leaf));
        Ok(())
    }
    fn put(
        &self,
        node: &Arc<Node>,
        route: &Hash,
        split_bit: Option<u8>,
        leaf: &Arc<Node>,
    ) -> Arc<Node> {
        if let Body::Branch { bit, left, right } = &node.body
            && split_bit.is_none_or(|s| *bit < s)
        {
            return if side(route, *bit) {
                self.branch(*bit, left.clone(), self.put(right, route, split_bit, leaf))
            } else {
                self.branch(*bit, self.put(left, route, split_bit, leaf), right.clone())
            };
        }
        match split_bit {
            None => leaf.clone(),
            Some(bit) if side(route, bit) => self.branch(bit, node.clone(), leaf.clone()),
            Some(bit) => self.branch(bit, leaf.clone(), node.clone()),
        }
    }
    fn remove(&mut self, key: &[u8]) -> Result<bool, Collision> {
        if self.get(key)?.is_none() {
            return Ok(false);
        }
        let route = self.route(key);
        self.root = self.cut(self.root.as_ref().unwrap(), &route);
        Ok(true)
    }
    fn cut(&self, node: &Arc<Node>, route: &Hash) -> Option<Arc<Node>> {
        match &node.body {
            Body::Leaf { .. } => None,
            Body::Branch { bit, left, right } => {
                if side(route, *bit) {
                    Some(
                        self.cut(right, route)
                            .map_or_else(|| left.clone(), |r| self.branch(*bit, left.clone(), r)),
                    )
                } else {
                    Some(
                        self.cut(left, route)
                            .map_or_else(|| right.clone(), |l| self.branch(*bit, l, right.clone())),
                    )
                }
            }
        }
    }
    // Validates complete in-memory structure, not a disk decoder or reload.
    fn validate(&self) -> bool {
        self.root
            .as_ref()
            .is_none_or(|root| self.check(root, None).is_some())
    }
    fn check(&self, node: &Node, parent_bit: Option<u8>) -> Option<(Hash, Hash)> {
        if node.hash == digest(&[EMPTY, &self.tag]) {
            return None;
        }
        match &node.body {
            Body::Leaf { route, key, value } => (*route == self.route(key)
                && node.hash == digest(&[LEAF, &self.tag, &bytes(key), &bytes(value)]))
            .then_some((*route, *route)),
            Body::Branch { bit, left, right } => {
                if parent_bit.is_some_and(|p| *bit <= p) {
                    return None;
                }
                let (lmin, lmax) = self.check(left, Some(*bit))?;
                let (rmin, rmax) = self.check(right, Some(*bit))?;
                (split(&lmin, &rmax) == Some(*bit)
                    && !side(&lmin, *bit)
                    && !side(&lmax, *bit)
                    && side(&rmin, *bit)
                    && side(&rmax, *bit)
                    && node.hash == digest(&[BRANCH, &self.tag, &[*bit], &left.hash, &right.hash]))
                .then_some((lmin, rmax))
            }
        }
    }
    fn depth(&self) -> usize {
        fn visit(n: &Node) -> usize {
            match &n.body {
                Body::Leaf { .. } => 0,
                Body::Branch { left, right, .. } => 1 + visit(left).max(visit(right)),
            }
        }
        self.root.as_ref().map_or(0, |n| visit(n))
    }
}

pub fn calibrate() {
    use std::hint::black_box;
    for count in [1_u64, 256, 4096] {
        for value_bytes in [32, 512] {
            let mut map = Map::new(BigUint::from(1_u8));
            for i in 0..count {
                map.insert(i.to_be_bytes().to_vec(), vec![0x5a; value_bytes])
                    .unwrap();
            }
            assert!(map.validate());
            let root = map.root_hash();
            let key = (count / 2).to_be_bytes();
            let absent = count.to_be_bytes();
            println!(
                "{{\"kind\":\"typed_map_corpus\",\"records\":{count},\"key_bytes\":8,\"value_bytes\":{value_bytes},\"maximum_path\":{},\"storage\":\"in_memory_arc\",\"canonical_records\":false}}",
                map.depth()
            );
            let suffix = format!("n{count}_v{value_bytes}");
            crate::measure(&format!("map_present_{suffix}"), || {
                map.get(black_box(&key)).unwrap().is_some()
            });
            crate::measure(&format!("map_absent_{suffix}"), || {
                map.get(black_box(&absent)).unwrap().is_none()
            });
            crate::measure(&format!("map_insert_path_copy_{suffix}"), || {
                let mut child = map.clone();
                child
                    .insert(
                        black_box(absent.to_vec()),
                        black_box(vec![0x6a; value_bytes]),
                    )
                    .unwrap();
                black_box(child.root_hash()) != root
            });
            crate::measure(&format!("map_replace_path_copy_{suffix}"), || {
                let mut child = map.clone();
                child
                    .insert(black_box(key.to_vec()), black_box(vec![0x6b; value_bytes]))
                    .unwrap();
                black_box(child.root_hash()) != root
            });
            crate::measure(&format!("map_delete_path_copy_{suffix}"), || {
                let mut child = map.clone();
                child.remove(black_box(&key)).unwrap() && black_box(child.root_hash()) != root
            });
            crate::measure(&format!("map_validate_memory_tree_{suffix}"), || {
                black_box(&map).validate()
            });
        }
    }
}

#[cfg(test)]
mod tests;
