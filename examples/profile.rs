use anyhow::Result;
use nom::combinator::all_consuming;
use nom::error::ParseError;
use nom::sequence::tuple;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{char, multispace0, satisfy},
    combinator::{recognize, value},
    multi::{many0, separated_list0},
    sequence::{delimited, pair}, IResult,
};
use std::env;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::os::unix::process::CommandExt;

const ENV_FS_RO_NAME: &str = "LL_FS_RO";
const ENV_FS_RW_NAME: &str = "LL_FS_RW";

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum EnvVar {
    RO,
    RW,
}

#[derive(Clone, Debug)]
enum Line {
    Comment,
    EnvVar(EnvVar, Vec<PathBuf>),
}

/// 
/// A combinator that takes a parser `inner` and produces a parser that also consumes both
/// leading and trailing whitespace, returning the output of `inner`.
///
/// From nom recipes:
/// https://docs.rs/nom/6.1.2/nom/recipes/index.html#wrapper-combinators-that-eat-whitespace-before-and-after-a-parser
///
fn ws<'a, F: 'a, O, E: ParseError<&'a str>>(
    inner: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    F: Fn(&'a str) -> IResult<&'a str, O, E>,
{
    delimited(multispace0, inner, multispace0)
}

///
/// A parser for one-line comments.
///
/// From nom recipes:
/// https://docs.rs/nom/6.1.2/nom/recipes/index.html#-ceol-style-comments
///
fn comment<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Line, E> {
    value(Line::Comment, pair(char('#'), is_not("\n\r")))(input)
}

///
/// Parses a single element of a path (file or directory name).
///
/// Note that in order to be extra safe only alphanumerical and underscore characters are
/// available, e.g. no '.' and no '-'.
///
/// TODO: relax constraints?
///
pub fn filename(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        satisfy(|c| matches!(c, '0'..='9' | 'A'..='Z' | 'a'..='z')),
        many0(satisfy(|c| matches!(c, '0'..='9' | 'A'..='Z' | 'a'..='z'))),
    ))(input)
}

///
/// Parses a single path.
///
/// Note that it is currently restricted to absolute paths.
///
/// TODO: allow relative paths?
///
fn parse_path(input: &str) -> IResult<&str, PathBuf> {
    let path = PathBuf::from("/");
    let (input, _) = tag("/")(input)?;
    separated_list0(tag("/"), filename)(input)
        .map(|(i, vs)| (i, vs.iter().fold(path, |p, s| p.join(s))))
}

///
/// Parses a path list separated with colons.
///
/// # Examples
///
/// ```
/// let paths = parse_path_list("/usr/lib:/bin:/tmp");
///
/// assert_eq!(paths, Ok("", vec!["/usr/lib", "/bin", "/tmp"]));
/// ```
///
fn parse_path_list(i: &str) -> IResult<&str, Vec<PathBuf>> {
    separated_list0(tag(":"), parse_path)(i)
}

///
/// Parses the name of an environment variable, currently the only two choices available are LL_FS_RO and LL_FS_RW.
///
/// # Examples
///
/// ```
/// let env = parse_env_var_name("LL_FS_RO");
///
/// assert_eq!(env, Ok(EnvVar::RO));
/// ```
fn parse_env_var_name(i: &str) -> IResult<&str, EnvVar> {
    let ro = value(EnvVar::RO, tag(ENV_FS_RO_NAME));
    let rw = value(EnvVar::RW, tag(ENV_FS_RW_NAME));
    alt((ro, rw))(i)
}

///
/// Parses a environment variable associated to a value.
///
/// # Examples
///
fn parse_env(input: &str) -> IResult<&str, Line> {
    tuple((
        parse_env_var_name,
        ws(tag("=")),
        delimited(tag("\""), parse_path_list, tag("\"")),
    ))(input)
    .map(|(i, (e, _, p))| (i, Line::EnvVar(e, p)))
}

///
/// Parses the entire profile without any further processing. This function is intended to be
/// internal. In case you want to actually parse a profile, use the `parse_profile` function
/// instead.
///
fn internal_parse_profile(input: &str) -> Vec<(EnvVar, Vec<PathBuf>)> {
    all_consuming(many0(alt((ws(parse_env), ws(comment)))))(input)
        .unwrap()
        .1
        .into_iter()
        .filter_map(|line| {
            if let Line::EnvVar(name, paths) = line {
                Some((name, paths))
            } else {
                None
            }
        })
        .collect::<Vec<(EnvVar, Vec<PathBuf>)>>()
}

///
/// Parses landlock profile from a string. This function takes care of parsing the profile
/// contained within the string and then groups rules according to their type (RW, RO).
///
/// For example:
///
///   LL_FS_RO="/tmp:/bin"
///   LL_FS_RO="/usr"
///   LL_FS_RW="/lib"
///
/// Produces the following:
///
///   EnvVar::RO => ["/tmp", "/bin", "/usr"]
///   EnvVar::RW => ["/lib"]
///
fn parse_profile(input: &str) -> HashMap<EnvVar, Vec<PathBuf>> {
    internal_parse_profile(input)
        .into_iter()
        .fold(HashMap::new(), |mut map, (var, mut paths)| {
            map.entry(var)
                .and_modify(|entry| {
                    entry.append(&mut paths);
                })
                .or_insert(paths);
            map
        })
}

fn main() -> Result<()> {
    let mut config_base = PathBuf::from(std::env::var("HOME")?);
    config_base.push(".config/landlock");

    let args: Vec<_> = env::args_os().collect();
    let program_name = args.get(0).map(|s| s.to_string_lossy()).unwrap_or_default();

    if args.len() < 2 {
        eprintln!("usage: {} <cmd> [args]...\n", program_name);
        eprintln!("Launch a command in a restricted environment.\n");
        eprintln!("This utility will load a profile found in ~/.config/landlock/file_<cmd>.ll.");
        eprintln!(
            "\nexample:\n\
                {} bash -i",
            program_name
        );
        eprintln!("Will load a profile from ~/.config/landlock/file_bash.ll");
        return Ok(());
    }

    let cmd_name = args.get(1).map(|s| s.to_string_lossy()).unwrap();

    config_base.push(format!("file_{}.ll", cmd_name));
    let profile = std::fs::read_to_string(config_base)?;

    let profile = parse_profile(&profile);
    // TODO: no more hardcoding
    let mut sandboxer = Command::new("./target/release/examples/sandboxer");

    for (e, paths) in profile {
        let varname = match e {
            EnvVar::RO => "LL_FS_RO",
            EnvVar::RW => "LL_FS_RW",
        };
        let arg: Vec<String> = paths.into_iter().map(|p| p.to_string_lossy().to_string()).collect();
        sandboxer.env(varname, &arg.join(":"));
    }

    Err(sandboxer
        .args(env::args().skip(1))
        .exec()
        .into())
}
