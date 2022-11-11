use std::{
    fs::File,
    io::{Read, Write, Seek, SeekFrom},
    path::Path,
    time::SystemTime,
};

use clap::{command, Parser, Subcommand};
use color_eyre::{eyre::Context, Result};
use flate2::{read::GzEncoder, Compression};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use tar::Header;

/// For each file, analysis of the file's entropy is computed, and a decision to either compress or not compress the file is made.
enum EntropyAnalysis {
    Compress,
    DontCompress,
}

/// The threshold of the entropy, at which any file with entropy above this threshold will not be compressed.
const ENTROPY_THRESHOLD: f32 = 6.5f32;

/// The percentage of the file to sample to compute the entropy.
const ENTROPY_SAMPLING: f32 = 0.5f32;

/// The name of the internal file in the tar archive that contains the files that were compressed.
const TTARE_COMPRESS_FILE_NAME: &str = ".ttare.tar.gz";

#[derive(Parser, Debug)]
#[command(author, version, about)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Compresses a list of files
    Compress {
        /// The files to compress
        files: Vec<String>,

        /// The destination ttare file
        #[arg(short, long)]
        output_file: String,

        /// The percentage of the file to sample to compute the entropy.
        #[arg(short, long)]
        sample_percentage: Option<f32>,

        /// The threshold of the entropy, at which any file with entropy above this threshold will not be compressed.
        #[arg(short, long)]
        entropy_threshold: Option<f32>,
    },

    /// Decompresses a ttare file
    Decompress {
        /// The ttare file to decompress
        input_file: String,

        /// The destination directory. Defaults to the current directory.
        #[arg(short, long)]
        output_dir: Option<String>,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;
    
    let args = Cli::parse();

    match args.command {
        Commands::Compress {
            files,
            output_file,
            sample_percentage,
            entropy_threshold,
        } => {
            compress(
                files,
                output_file,
                sample_percentage.unwrap_or(ENTROPY_SAMPLING),
                entropy_threshold.unwrap_or(ENTROPY_THRESHOLD),
            )?;
        }
        Commands::Decompress {
            input_file,
            output_dir,
        } => {}
    }

    Ok(())
}

fn compress(
    files: Vec<String>,
    output_file: String,
    entropy_sampling: f32,
    entropy_threshold: f32,
) -> Result<()> {
    let mut root_tar = tar::Builder::new(Vec::new());
    let mut compress_tar = tar::Builder::new(Vec::new());

    for file_name in files {
        // Open the file
        let mut file = File::open(&file_name).with_context(|| "Failed to open file")?;

        let analysis_result = analyze_entropy(&mut file, entropy_sampling, entropy_threshold)?;

        file.seek(SeekFrom::Start(0))?;
        
        // Add the file to the correct tar
        match analysis_result {
            EntropyAnalysis::Compress => {
                compress_tar.append_file(Path::new(&file_name), &mut file)?;
            }
            EntropyAnalysis::DontCompress => {
                root_tar.append_file(Path::new(&file_name), &mut file)?;
            }
        }
    }

    // Write the compressed tar to the root tar
    let compress_tar = compress_tar.into_inner()?;

    // compress it
    let mut encoder = GzEncoder::new(compress_tar.as_slice(), Compression::default());
    let mut compressed_buf = vec![];
    encoder.read_to_end(&mut compressed_buf)?;

    // Create the header for the compressed tar
    let mut header = Header::new_gnu();
    header.set_size(compressed_buf.len() as u64);
    header.set_mode(32 | 4 | 256);
    header.set_mtime(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as u64,
    );
    header.set_cksum();

    // Add it to the root tar
    root_tar.append_data(
        &mut header,
        Path::new(TTARE_COMPRESS_FILE_NAME),
        compressed_buf.as_slice(),
    )?;

    // Write the root tar to the output file
    let root_tar = root_tar.into_inner()?;
    let mut output_file = File::create(output_file)?;
    output_file.write_all(&root_tar)?;

    Ok(())
}

fn analyze_entropy(
    file: &mut File,
    entropy_sampling: f32,
    entropy_threshold: f32,
) -> Result<EntropyAnalysis> {
    let entropy_bytes_len = (file.metadata()?.len() as f32 * entropy_sampling) as usize;

    // TODO: ideally this would randomly sample the file, but for the sake of speed,
    // read the first entropy_bytes_len bytes of the file
    let mut entropy_bytes = vec![0u8; entropy_bytes_len];
    file.read_exact(&mut entropy_bytes)?;

    let entropy = entropy(&entropy_bytes);

    if entropy > entropy_threshold {
        Ok(EntropyAnalysis::DontCompress)
    } else {
        Ok(EntropyAnalysis::Compress)
    }
}

fn entropy(entropy_bytes: &[u8]) -> f32 {
    let total = entropy_bytes.len() as f32;

    let counts = entropy_bytes
        .iter()
        .fold(FxHashMap::default(), |mut counts, byte| {
            *counts.entry(byte).or_insert(0) += 1;
            counts
        });

    counts
        .into_par_iter()
        .map(|(_, count)| {
            let p = count as f32 / total;
            -p * p.log2()
        })
        .sum()
}
