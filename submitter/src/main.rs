use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ethereum_types::{Address, U256};
use ethers::abi::{Abi, RawLog};
use ethers::providers::Middleware;
use ethers::types::Filter;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, Response, StatusCode, Url};
use serde_json::json;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "kebab-case")]
enum Cmd {
    /// LEGACY: Fetches identities from all events from the (legacy) smart contract
    Fetch(Fetch),
    /// Submit identities to the sequencer
    Submit(Submit),
    /// Consolidates multiple identity files into one
    ///
    /// Also serves as a validation tool (when used on a single file)
    Process(Process),
    /// Creates a diff between two identity files, useful for validating that the migration completed
    Diff(Diff),
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
struct Fetch {
    /// Output file
    #[clap(short, long)]
    output_file: PathBuf,

    /// The block at which to start fetching events
    #[clap(short, long)]
    from_block: u64,

    /// The block at which to stop fetching events
    ///
    /// If not specified, will be set to current latest block
    #[clap(short, long)]
    to_block: Option<u64>,

    /// Address of the smart contract
    #[clap(short, long)]
    address: Address,

    /// How many blocks to handle at once
    #[clap(short, long, default_value = "1000")]
    block_span: u64,

    /// Rpc url
    #[clap(short, long)]
    rpc_url: Url,
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
struct Submit {
    /// Input file with commitments
    #[clap(short, long)]
    input_file: PathBuf,

    /// Input file with commitments
    #[clap(short, long)]
    unprocessed_file: PathBuf,

    /// Sequencer URL
    #[clap(short, long)]
    sequencer_url: String,

    /// Window size for processing
    #[clap(short, long, default_value = "100")]
    window: usize,
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
struct Process {
    /// Files to consolidate
    #[clap(short, long)]
    files: Vec<PathBuf>,

    /// Output file
    #[clap(short, long)]
    output: PathBuf,
}

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
struct Diff {
    /// First file
    a: PathBuf,

    /// Second file
    b: PathBuf,

    /// Output file - where the diff will be written
    #[clap(short, long)]
    output: PathBuf,
}

async fn send_commitment(
    sequencer_url: &str,
    commitment: String,
) -> anyhow::Result<(String, Response)> {
    let url = format!("{sequencer_url}/insertIdentity");
    let client = Client::new();
    let body = json!({ "identityCommitment": commitment.as_str() });

    let response = client.post(url).json(&body).send().await?;

    Ok((commitment, response))
}

fn read_commitments_from_file(filename: impl AsRef<Path>) -> anyhow::Result<HashSet<String>> {
    let mut commitments = HashSet::new();
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        commitments.insert(line?);
    }

    Ok(commitments)
}

fn read_typed_commitments_from_file(filename: impl AsRef<Path>) -> anyhow::Result<HashSet<U256>> {
    let mut commitments = HashSet::new();
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let line = line.trim_start_matches("0x").trim();

        if line.is_empty() {
            continue;
        }

        let commitment = U256::from_str_radix(&line, 16)?;
        commitments.insert(commitment);
    }

    Ok(commitments)
}

fn save_unprocessed(
    unprocessed: &VecDeque<String>,
    filename: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(filename)?;

    let mut writer = BufWriter::new(&mut file);

    for commitment in unprocessed {
        writeln!(writer, "{}", commitment)?;
    }

    writer.flush()?;

    Ok(())
}

async fn submit(opt: Submit) -> anyhow::Result<()> {
    let commitments = read_commitments_from_file(&opt.input_file)?;
    let mut unprocessed: VecDeque<_> = commitments.iter().cloned().collect();

    let total = unprocessed.len();

    let progress = indicatif::ProgressBar::new(total as u64);
    progress.set_message("Processing...");

    loop {
        progress.set_position((total - unprocessed.len()) as u64);

        save_unprocessed(&unprocessed, &opt.unprocessed_file)?;

        if unprocessed.is_empty() {
            break;
        }

        let pending = FuturesUnordered::new();

        for _ in 0..opt.window {
            if let Some(commitment) = unprocessed.pop_front() {
                pending.push(send_commitment(&opt.sequencer_url, commitment.clone()));
            } else {
                break;
            }
        }

        let pending = pending.collect::<Vec<_>>().await;

        for res in pending {
            let (commitment, response) = res?;

            if !response.status().is_success() && response.status() != StatusCode::BAD_REQUEST {
                eprintln!("Commitment {commitment} will be processed later");
                unprocessed.push_back(commitment.clone());
            }

            if !response.status().is_success() {
                let status = response.status();
                let error = response.text().await?;
                eprintln!(
                "Failed to submit commitment {commitment} due to error {error}, status: {status}"
            );
            }
        }
    }

    Ok(())
}

async fn process(opt: Process) -> anyhow::Result<()> {
    let mut commitments = HashSet::new();

    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&opt.output)?;

    let mut writer = BufWriter::new(&mut output_file);

    for file in &opt.files {
        let file = File::open(&file)?;
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let line = line.trim_start_matches("0x").trim();
            if line.is_empty() {
                continue;
            }

            let commitment = U256::from_str_radix(line, 16)?;

            if commitments.insert(commitment) {
                writeln!(writer, "0x{:0>64X}", commitment)?;
            }
        }
    }

    writer.flush()?;

    Ok(())
}

async fn diff(opt: Diff) -> anyhow::Result<()> {
    let a = read_typed_commitments_from_file(&opt.a)?;
    let b = read_typed_commitments_from_file(&opt.b)?;

    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&opt.output)?;

    let mut writer = BufWriter::new(&mut output_file);

    for commitment in a.difference(&b) {
        writeln!(writer, "0x{:0>64X}", commitment)?;
    }

    writer.flush()?;

    Ok(())
}

async fn fetch(opt: Fetch) -> anyhow::Result<()> {
    const CONTRACT_ABI: &str = include_str!("./abi.json");

    let abi: Abi = serde_json::from_str(CONTRACT_ABI)?;
    let member_added = abi.event("MemberAdded")?.clone();

    let provider = ethers::providers::Http::new(opt.rpc_url);
    let provider = ethers::providers::Provider::new(provider);
    let provider = Arc::new(provider);

    let from_block = opt.from_block;
    let to_block = if let Some(to_block) = opt.to_block {
        to_block
    } else {
        provider.get_block_number().await?.0[0]
    };

    println!("Fetching events between blocks {from_block}-{to_block}");

    let topic = member_added.signature();

    let filter_base = Filter::new().address(opt.address).topic0(topic);

    let mut start_block = from_block;
    let mut end_block = start_block + opt.block_span;

    let mut identities = HashSet::new();

    let num_blocks = to_block - from_block;
    let style =
        ProgressStyle::with_template("[{elapsed_precise}] {bar} {pos:>7}/{len:7} {msg}").unwrap();
    let progress = ProgressBar::new(num_blocks).with_style(style);

    while start_block < to_block {
        if end_block > to_block {
            end_block = to_block;
        }

        progress.set_message(format!(
            "Fetching events from block {start_block} to {end_block}, found {} identities",
            identities.len()
        ));
        let position = start_block - from_block;
        progress.set_position(position);

        let filter = filter_base
            .clone()
            .from_block(start_block)
            .to_block(end_block);

        let logs = provider.get_logs(&filter).await?;

        for log in logs {
            let log: RawLog = log.into();

            let inputs = member_added.parse_log(log)?;
            if let Some(identity_commitment_param) = inputs
                .params
                .iter()
                .find(|param| param.name == "identityCommitment")
            {
                let identity_commitment_param = identity_commitment_param
                    .value
                    .clone()
                    .into_uint()
                    .ok_or_else(|| anyhow::anyhow!("Failed to parse identity commitment"))?;

                identities.insert(identity_commitment_param);
            }
        }

        fetch_update_output_file(&opt.output_file, &identities).await?;

        start_block += opt.block_span;
        end_block += opt.block_span;
    }

    progress.finish();

    Ok(())
}

async fn fetch_update_output_file(
    output_file: impl AsRef<Path>,
    identities: &HashSet<U256>,
) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_file)?;

    let mut writer = BufWriter::new(&mut file);

    for identity in identities {
        writeln!(writer, "0x{:0>64X}", identity)?;
    }

    writer.flush()?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    match opt.cmd {
        Cmd::Fetch(opt) => fetch(opt).await?,
        Cmd::Submit(opt) => submit(opt).await?,
        Cmd::Process(opt) => process(opt).await?,
        Cmd::Diff(opt) => diff(opt).await?,
    }

    Ok(())
}
