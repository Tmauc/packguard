use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DepKind {
    Runtime,
    Dev,
    Peer,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub declared_range: String,
    pub installed: Option<String>,
    pub kind: DepKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub ecosystem: &'static str,
    pub root: PathBuf,
    pub name: Option<String>,
    pub dependencies: Vec<Dependency>,
}
