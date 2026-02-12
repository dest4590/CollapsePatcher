use base64::prelude::*;
use clap::{Parser, Subcommand};
use rand::seq::SliceRandom;
use rand::RngExt;
use rayon::prelude::*;
use ristretto_classfile::attributes::{Attribute, Instruction, StackFrame};
use ristretto_classfile::{ClassFile, Constant, Field, FieldAccessFlags, FieldType};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

const XOR_KEY_BYTES: &[u8] = b"GODDAM_BRADAR";

const SIGNATURE_URL: &str = "https://collapseloader.org";
const WARDEN_INTERNAL_CLASS: &str = "org/collapseloader/agent/Warden";
const WARDEN_CLASS_ENTRY: &str = "org/collapseloader/agent/Warden.class";

const WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024;

const IGNORED_PACKAGES: &[&str] = &[
    "baritone/",
    "com/",
    "com/mojang/",
    "io/jsonwebtoken/",
    "io/netty/",
    "it/unimi/",
    "java/",
    "javafx/",
    "javax/",
    "joptsimple/",
    "kotlin/",
    "lombok/",
    "net/java/",
    "net/minecraft/",
    "net/minecraftforge/",
    "net/optifine/",
    "org/apache/",
    "org/joml/",
    "org/logging/",
    "org/luaj/",
    "org/lwjgl/",
    "org/objectweb/",
    "org/slf4j/",
    "org/yaml/snakeyaml/",
    "oshi/",
];

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[command(subcommand)]
    command: Command,
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    Patch { input: PathBuf },
    Watermark { input: PathBuf },
    Verify { input: PathBuf },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PatchMode {
    PatchWithWarden,
    WatermarkOnly,
}

fn run_progress_bar(
    counter: Arc<AtomicUsize>,
    err_counter: Option<Arc<AtomicUsize>>,
    total: usize,
    label: String,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let is_done = done.load(Ordering::Relaxed);
            let current = counter.load(Ordering::Relaxed);
            let errors = err_counter
                .as_ref()
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);

            let percent = if total > 0 {
                (current * 100) / total
            } else {
                100
            };

            if errors > 0 {
                print!("\r\x1b[2K>> {} [{}%, {} errors] ", label, percent, errors);
            } else {
                print!("\r\x1b[2K>> {} [{}%] ", label, percent);
            }
            std::io::stdout().flush().unwrap();

            if is_done {
                break;
            }

            thread::sleep(Duration::from_millis(50));
        }
        println!();
    })
}

#[inline]
fn encrypt_string(s: &str) -> String {
    let bytes: Vec<u8> = s
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY_BYTES[i % XOR_KEY_BYTES.len()])
        .collect();
    BASE64_STANDARD.encode(&bytes)
}

fn detect_target_packages(names: &[String]) -> Vec<String> {
    let mut package_counts: HashMap<String, usize> = HashMap::with_capacity(100);

    for name in names {
        if !name.ends_with(".class") || name == WARDEN_CLASS_ENTRY || name.starts_with("META-INF/")
        {
            continue;
        }

        if IGNORED_PACKAGES.iter().any(|&ig| name.starts_with(ig)) {
            continue;
        }

        let parts: Vec<&str> = name.split('/').collect();
        let depth = std::cmp::min(parts.len() - 1, 3);
        if depth > 0 {
            let root = parts[..depth].join("/") + "/";
            *package_counts.entry(root).or_insert(0) += 1;
        }
    }

    let mut pkgs: Vec<(String, usize)> = package_counts.into_iter().collect();
    pkgs.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    let mut rng = rand::rng();
    let available = pkgs.len();
    if available == 0 {
        return Vec::new();
    }

    let min_select = if available >= 3 { 3 } else { available };
    let max_select = std::cmp::min(5, available);
    let count = if min_select == max_select {
        min_select
    } else {
        rng.random_range(min_select..=max_select)
    };

    pkgs.into_iter().take(count).map(|(pkg, _)| pkg).collect()
}

#[derive(Clone)]
struct EntryMeta {
    name: String,
    is_signature: bool,
    is_class: bool,
    is_warden: bool,
    should_encrypt: bool,
    should_watermark: bool,
}

struct PatchItem {
    idx: usize,
    do_warden: bool,
    do_watermark: bool,
    bytes: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    match opts.command {
        Command::Verify { input } => {
            let input_path = input.as_path();
            println!(">> checking integrity of: {}", input_path.display());
            let file = File::open(input_path)?;
            let mut raw_input = Vec::with_capacity(file.metadata()?.len() as usize);
            let mut reader = std::io::BufReader::new(file);
            reader.read_to_end(&mut raw_input)?;

            match verify_jar_bytes(&raw_input) {
                Ok(true) => println!(">> result: verified. this JAR is signed and secure."),
                Ok(false) => {
                    println!(">> result: negative. no CollapseLoader signature found here.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!(">> error: something went wrong during verification: {}", e);
                    std::process::exit(2);
                }
            }
            return Ok(());
        }
        Command::Patch { input } => {
            let input_path = input.as_path();
            let output_path = if let Some(o) = opts.out.as_ref() {
                o.clone()
            } else {
                input_path.with_file_name(format!(
                    "{}-patched.jar",
                    input_path.file_stem().unwrap().to_string_lossy()
                ))
            };

            patch_jar(input_path, &output_path, PatchMode::PatchWithWarden)
        }
        Command::Watermark { input } => {
            let input_path = input.as_path();
            let output_path = if let Some(o) = opts.out.as_ref() {
                o.clone()
            } else {
                input_path.with_file_name(format!(
                    "{}-watermarked.jar",
                    input_path.file_stem().unwrap().to_string_lossy()
                ))
            };

            patch_jar(input_path, &output_path, PatchMode::WatermarkOnly)
        }
    }
}

fn patch_jar(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    mode: PatchMode,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(">> scanning source jar: {}", input_path.display());

    let file = File::open(input_path)?;
    let reader = BufReader::new(file);
    let mut zip_in = ZipArchive::new(reader)?;

    let out_file = File::create(output_path)?;
    let buf_writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, out_file);
    let mut zip_out = ZipWriter::new(buf_writer);

    let zip_comment = match mode {
        PatchMode::PatchWithWarden => {
            format!("Signed by CollapseLoader with Warden ({})", SIGNATURE_URL)
        }
        PatchMode::WatermarkOnly => {
            format!("Signed by CollapseLoader watermark ({})", SIGNATURE_URL)
        }
    };
    zip_out.set_comment(zip_comment);

    let len = zip_in.len();

    let mut entries: Vec<EntryMeta> = Vec::with_capacity(len);
    let mut filenames: Vec<String> = Vec::with_capacity(len);

    println!(">> indexing entries...");

    for i in 0..len {
        let file = zip_in.by_index(i)?;
        let name = file.name().to_string();

        let is_signature = name.starts_with("META-INF/")
            && (name.ends_with(".SF") || name.ends_with(".RSA") || name.ends_with(".DSA"));
        let is_class = name.ends_with(".class");
        let is_warden = name == WARDEN_CLASS_ENTRY;

        filenames.push(name.clone());
        entries.push(EntryMeta {
            name,
            is_signature,
            is_class,
            is_warden,
            should_encrypt: false,
            should_watermark: false,
        });
    }

    let target_packages = detect_target_packages(&filenames);

    if target_packages.is_empty() {
        println!(">> warning: couldn't pin down any main client packages. safe mode engaged.");
        if mode == PatchMode::PatchWithWarden {
            println!(">> no viable targets for encryption. applying watermarks only.");
        }
    } else {
        println!(">> targets acquired: {}.", target_packages.join(", "));
    }

    let in_target_or_safe_mode = |name: &str| -> bool {
        target_packages.is_empty() || target_packages.iter().any(|pkg| name.starts_with(pkg))
    };

    let mut eligible_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.is_class
                && !e.is_signature
                && !e.is_warden
                && in_target_or_safe_mode(&e.name)
                && !e.name.contains("Main")
                && !e.name.contains("Mixin")
                && !e.name.contains("mixin")
        })
        .map(|(i, _)| i)
        .collect();

    let total_classes = eligible_indices.len();
    println!(">> eligible classes: {}", total_classes);

    let mut rng = rand::rng();
    eligible_indices.shuffle(&mut rng);

    match mode {
        PatchMode::PatchWithWarden => {
            let percent = if total_classes > 0 {
                rng.random_range(30..=60)
            } else {
                0
            };
            let count_to_encrypt = std::cmp::max(
                (total_classes * percent) / 100,
                if total_classes > 0 { 1 } else { 0 },
            );

            for &idx in eligible_indices.iter().take(count_to_encrypt) {
                entries[idx].should_encrypt = true;
                entries[idx].should_watermark = true;
            }

            let desired_watermarks = rng.random_range(10..=30);
            let sample_size = std::cmp::min(desired_watermarks, eligible_indices.len());

            let mut w_count = 0;
            for &idx in &eligible_indices {
                if w_count >= sample_size {
                    break;
                }
                if !entries[idx].should_encrypt {
                    entries[idx].should_watermark = true;
                    w_count += 1;
                }
            }

            println!(">> encrypting {} classes.", count_to_encrypt);
        }
        PatchMode::WatermarkOnly => {
            let desired_watermarks = rng.random_range(10..=30);
            let sample_size = std::cmp::min(desired_watermarks, eligible_indices.len());
            for &idx in eligible_indices.iter().take(sample_size) {
                entries[idx].should_watermark = true;
            }

            println!(">> watermarking {} classes.", sample_size);
        }
    }

    let indices_to_patch: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if e.should_encrypt || e.should_watermark {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    let mut reader = zip_in.into_inner();
    reader.seek(SeekFrom::Start(0))?;
    let mut zip_in = ZipArchive::new(reader)?;

    println!(">> reading selected entries...");
    let mut patch_items: Vec<PatchItem> = Vec::with_capacity(indices_to_patch.len());
    for idx in &indices_to_patch {
        let mut file = zip_in.by_index(*idx)?;
        let mut buf = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buf)?;
        patch_items.push(PatchItem {
            idx: *idx,
            do_warden: entries[*idx].should_encrypt,
            do_watermark: entries[*idx].should_watermark,
            bytes: buf,
        });
    }

    let patch_counter = Arc::new(AtomicUsize::new(0));
    let error_counter = Arc::new(AtomicUsize::new(0));
    let items_to_process = patch_items.len();
    let done_flag = Arc::new(AtomicBool::new(false));

    let progress_label = match mode {
        PatchMode::PatchWithWarden => "patching classes",
        PatchMode::WatermarkOnly => "watermarking classes",
    }
    .to_string();

    let p_thread = run_progress_bar(
        patch_counter.clone(),
        Some(error_counter.clone()),
        items_to_process,
        progress_label,
        done_flag.clone(),
    );

    patch_items.par_iter_mut().for_each(|item| {
        match process_class(&item.bytes, item.do_warden, item.do_watermark) {
            Ok(patched) => {
                item.bytes = patched;
            }
            Err(_) => {
                error_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        patch_counter.fetch_add(1, Ordering::Relaxed);
    });

    done_flag.store(true, Ordering::Relaxed);
    p_thread.join().unwrap();

    let mut patched_bytes: Vec<Option<Vec<u8>>> = vec![None; entries.len()];
    for item in patch_items {
        patched_bytes[item.idx] = Some(item.bytes);
    }

    let mut reader = zip_in.into_inner();
    reader.seek(SeekFrom::Start(0))?;
    let mut zip_in = ZipArchive::new(reader)?;

    let write_counter = Arc::new(AtomicUsize::new(0));
    let write_total = entries.len();
    let done_write_flag = Arc::new(AtomicBool::new(false));

    let w_thread = run_progress_bar(
        write_counter.clone(),
        None,
        write_total,
        "rebuilding JAR".to_string(),
        done_write_flag.clone(),
    );

    let mut patched_count = 0;
    let patched_options =
        FileOptions::<()>::default().compression_method(zip::CompressionMethod::Deflated);

    for (i, meta) in entries.iter().enumerate() {
        if meta.is_signature || meta.is_warden {
            write_counter.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        if let Some(bytes) = patched_bytes[i].as_ref() {
            zip_out.start_file(&meta.name, patched_options)?;
            zip_out.write_all(bytes)?;
            patched_count += 1;
        } else {
            let file = zip_in.by_index(i)?;
            zip_out.raw_copy_file(file)?;
        }

        write_counter.fetch_add(1, Ordering::Relaxed);
    }

    done_write_flag.store(true, Ordering::Relaxed);
    w_thread.join().unwrap();
    zip_out.finish()?;

    println!(">> all done. modified {} files.", patched_count);
    println!(">> output saved to: {}", output_path.display());
    Ok(())
}

fn process_class(
    original_bytes: &[u8],
    do_warden: bool,
    do_watermark: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut cursor = Cursor::new(original_bytes.to_vec());
    let mut class_file = ClassFile::from_bytes(&mut cursor)?;
    let mut modified = false;

    if do_warden {
        let warden_class_index = class_file.constant_pool.add_class(WARDEN_INTERNAL_CLASS)?;
        let warden_decrypt_ref = class_file.constant_pool.add_method_ref(
            warden_class_index,
            "decrypt",
            "(Ljava/lang/String;)Ljava/lang/String;",
        )?;

        let mut new_code = Vec::with_capacity(2048);
        let mut mapping: Vec<u16> = Vec::with_capacity(2048);

        for method in &mut class_file.methods {
            if let Some(Attribute::Code {
                code,
                exception_table,
                attributes,
                ..
            }) = method
                .attributes
                .iter_mut()
                .find(|a| matches!(a, Attribute::Code { .. }))
            {
                new_code.clear();
                new_code.reserve(code.len() + 100);
                mapping.clear();
                mapping.resize(code.len().saturating_add(1), 0);

                let mut code_changed = false;

                for (old_idx, instr) in code.iter().enumerate() {
                    let current_new_idx = new_code.len() as u16;
                    if let Some(slot) = mapping.get_mut(old_idx) {
                        *slot = current_new_idx;
                    }

                    match instr {
                        Instruction::Ldc(idx8) => {
                            let idx = *idx8 as u16;
                            let is_target = matches!(
                                class_file.constant_pool.try_get(idx),
                                Ok(Constant::String(_))
                            );

                            if is_target {
                                let str_val =
                                    class_file.constant_pool.try_get_string(idx)?.to_string();

                                if str_val.len() > 1 {
                                    let encrypted = encrypt_string(&str_val);
                                    let new_str_idx =
                                        class_file.constant_pool.add_string(encrypted)?;

                                    if new_str_idx <= 255 {
                                        new_code.push(Instruction::Ldc(new_str_idx as u8));
                                    } else {
                                        new_code.push(Instruction::Ldc_w(new_str_idx));
                                    }
                                    new_code.push(Instruction::Invokestatic(warden_decrypt_ref));
                                    code_changed = true;
                                } else {
                                    new_code.push(instr.clone());
                                }
                            } else {
                                new_code.push(instr.clone());
                            }
                        }
                        Instruction::Ldc_w(idx16) => {
                            let idx = *idx16;
                            let is_target = matches!(
                                class_file.constant_pool.try_get(idx),
                                Ok(Constant::String(_))
                            );

                            if is_target {
                                let str_val =
                                    class_file.constant_pool.try_get_string(idx)?.to_string();
                                if str_val.len() > 1 {
                                    let encrypted = encrypt_string(&str_val);
                                    let new_str_idx =
                                        class_file.constant_pool.add_string(encrypted)?;

                                    if new_str_idx <= 255 {
                                        new_code.push(Instruction::Ldc(new_str_idx as u8));
                                    } else {
                                        new_code.push(Instruction::Ldc_w(new_str_idx));
                                    }
                                    new_code.push(Instruction::Invokestatic(warden_decrypt_ref));
                                    code_changed = true;
                                } else {
                                    new_code.push(instr.clone());
                                }
                            } else {
                                new_code.push(instr.clone());
                            }
                        }
                        _ => {
                            new_code.push(instr.clone());
                        }
                    }
                }

                let final_new_len = new_code.len() as u16;
                let final_old_len = code.len() as u16;
                if let Some(slot) = mapping.get_mut(final_old_len as usize) {
                    *slot = final_new_len;
                }

                if code_changed {
                    let map_idx =
                        |idx: u16| -> u16 { mapping.get(idx as usize).copied().unwrap_or(idx) };

                    for instr in &mut new_code {
                        match instr {
                            Instruction::Ifeq(o)
                            | Instruction::Ifne(o)
                            | Instruction::Iflt(o)
                            | Instruction::Ifge(o)
                            | Instruction::Ifgt(o)
                            | Instruction::Ifle(o)
                            | Instruction::If_icmpeq(o)
                            | Instruction::If_icmpne(o)
                            | Instruction::If_icmplt(o)
                            | Instruction::If_icmpge(o)
                            | Instruction::If_icmpgt(o)
                            | Instruction::If_icmple(o)
                            | Instruction::If_acmpeq(o)
                            | Instruction::If_acmpne(o)
                            | Instruction::Goto(o)
                            | Instruction::Jsr(o)
                            | Instruction::Ifnull(o)
                            | Instruction::Ifnonnull(o) => {
                                *o = map_idx(*o);
                            }
                            Instruction::Goto_w(o) | Instruction::Jsr_w(o) => {
                                if let Ok(idx) = u16::try_from(*o) {
                                    *o = map_idx(idx) as i32;
                                }
                            }
                            Instruction::Tableswitch(ts) => {
                                for offset in &mut ts.offsets {
                                    if let Ok(idx) = u16::try_from(*offset) {
                                        *offset = map_idx(idx) as i32;
                                    }
                                }
                                if let Ok(idx) = u16::try_from(ts.default) {
                                    ts.default = map_idx(idx) as i32;
                                }
                            }
                            Instruction::Lookupswitch(ls) => {
                                for offset in ls.pairs.values_mut() {
                                    if let Ok(idx) = u16::try_from(*offset) {
                                        *offset = map_idx(idx) as i32;
                                    }
                                }
                                if let Ok(idx) = u16::try_from(ls.default) {
                                    ls.default = map_idx(idx) as i32;
                                }
                            }
                            _ => {}
                        }
                    }

                    for ex in exception_table.iter_mut() {
                        ex.range_pc.start = map_idx(ex.range_pc.start);
                        ex.range_pc.end = map_idx(ex.range_pc.end);
                        ex.handler_pc = map_idx(ex.handler_pc);
                    }

                    if let Some(Attribute::StackMapTable { frames, .. }) = attributes
                        .iter_mut()
                        .find(|a| matches!(a, Attribute::StackMapTable { .. }))
                    {
                        let mut new_frames = Vec::with_capacity(frames.len());
                        let mut current_idx: u16 = 0;
                        let mut last_new_idx: u16 = 0;

                        for (i, frame) in frames.iter().enumerate() {
                            let delta = frame.offset_delta();
                            let abs_idx = if i == 0 {
                                delta
                            } else {
                                current_idx + delta + 1
                            };
                            current_idx = abs_idx;

                            let new_abs_idx = map_idx(abs_idx);
                            let new_delta = if i == 0 {
                                new_abs_idx
                            } else {
                                new_abs_idx.saturating_sub(last_new_idx.saturating_add(1))
                            };
                            last_new_idx = new_abs_idx;

                            let new_frame = match frame {
                                StackFrame::SameFrame { .. } => {
                                    if new_delta <= 63 {
                                        StackFrame::SameFrame {
                                            frame_type: new_delta as u8,
                                        }
                                    } else {
                                        StackFrame::SameFrameExtended {
                                            frame_type: 251,
                                            offset_delta: new_delta,
                                        }
                                    }
                                }
                                StackFrame::SameLocals1StackItemFrame { stack, .. } => {
                                    if new_delta <= 63 {
                                        StackFrame::SameLocals1StackItemFrame {
                                            frame_type: (new_delta + 64) as u8,
                                            stack: stack.clone(),
                                        }
                                    } else {
                                        StackFrame::SameLocals1StackItemFrameExtended {
                                            frame_type: 247,
                                            offset_delta: new_delta,
                                            stack: stack.clone(),
                                        }
                                    }
                                }
                                StackFrame::SameLocals1StackItemFrameExtended {
                                    frame_type,
                                    stack,
                                    ..
                                } => StackFrame::SameLocals1StackItemFrameExtended {
                                    frame_type: *frame_type,
                                    offset_delta: new_delta,
                                    stack: stack.clone(),
                                },
                                StackFrame::ChopFrame { frame_type, .. } => StackFrame::ChopFrame {
                                    frame_type: *frame_type,
                                    offset_delta: new_delta,
                                },
                                StackFrame::SameFrameExtended { frame_type, .. } => {
                                    StackFrame::SameFrameExtended {
                                        frame_type: *frame_type,
                                        offset_delta: new_delta,
                                    }
                                }
                                StackFrame::AppendFrame {
                                    frame_type, locals, ..
                                } => StackFrame::AppendFrame {
                                    frame_type: *frame_type,
                                    offset_delta: new_delta,
                                    locals: locals.clone(),
                                },
                                StackFrame::FullFrame {
                                    frame_type,
                                    locals,
                                    stack,
                                    ..
                                } => StackFrame::FullFrame {
                                    frame_type: *frame_type,
                                    offset_delta: new_delta,
                                    locals: locals.clone(),
                                    stack: stack.clone(),
                                },
                            };
                            new_frames.push(new_frame);
                        }
                        *frames = new_frames;
                    }

                    if let Some(Attribute::LineNumberTable { line_numbers, .. }) = attributes
                        .iter_mut()
                        .find(|a| matches!(a, Attribute::LineNumberTable { .. }))
                    {
                        for ln in line_numbers.iter_mut() {
                            ln.start_pc = map_idx(ln.start_pc);
                        }
                    }

                    if let Some(Attribute::LocalVariableTable { variables, .. }) = attributes
                        .iter_mut()
                        .find(|a| matches!(a, Attribute::LocalVariableTable { .. }))
                    {
                        for var in variables.iter_mut() {
                            let old_start = var.start_pc;
                            let old_end_u32 = u32::from(old_start) + u32::from(var.length);
                            let old_end =
                                u16::try_from(std::cmp::min(old_end_u32, u32::from(u16::MAX)))
                                    .unwrap_or(u16::MAX);

                            var.start_pc = map_idx(old_start);
                            let new_end = map_idx(old_end);
                            var.length = new_end.saturating_sub(var.start_pc);
                        }
                    }

                    std::mem::swap(code, &mut new_code);
                    modified = true;
                }
            }
        }
    }
    if do_watermark {
        let mut rng = rand::rng();

        let var_name: String = format!(
            "cl_{}",
            (0..6)
                .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
                .collect::<String>()
        );

        let encoded_value = BASE64_STANDARD.encode(SIGNATURE_URL);

        let string_idx = class_file.constant_pool.add_string(&encoded_value)?;
        let name_idx = class_file.constant_pool.add_utf8(&var_name)?;
        let desc_idx = class_file.constant_pool.add_utf8("Ljava/lang/String;")?;
        let attr_name_idx = class_file.constant_pool.add_utf8("ConstantValue")?;

        let constant_value_attr = Attribute::ConstantValue {
            name_index: attr_name_idx,
            constant_value_index: string_idx,
        };

        let field = Field {
            access_flags: FieldAccessFlags::PUBLIC
                | FieldAccessFlags::STATIC
                | FieldAccessFlags::FINAL
                | FieldAccessFlags::SYNTHETIC,
            name_index: name_idx,
            descriptor_index: desc_idx,
            attributes: vec![constant_value_attr],
            field_type: FieldType::Object("java/lang/String".to_string()),
        };
        class_file.fields.push(field);

        modified = true;
    }

    if !modified {
        return Ok(cursor.into_inner());
    }

    let mut out_buffer = Vec::with_capacity(original_bytes.len() + 1024);
    class_file.to_bytes(&mut out_buffer)?;
    Ok(out_buffer)
}

fn verify_jar_bytes(buffer: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let cursor = Cursor::new(buffer);
    let mut zip_in = ZipArchive::new(cursor)?;
    let comment = zip_in.comment();
    let comment_str = String::from_utf8_lossy(comment);
    let has_zip_sig = comment_str.contains(SIGNATURE_URL);

    let encoded_value = BASE64_STANDARD.encode(SIGNATURE_URL);
    let fake_signature = "Lcom/collapseloader/Signed;";
    let mut found_marker = false;

    for i in 0..zip_in.len() {
        let mut file = zip_in.by_index(i)?;
        let name = file.name().to_string();
        if !name.ends_with(".class") {
            continue;
        }
        let mut buf = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buf)?;
        let mut cursor = Cursor::new(buf);

        if let Ok(class_file) = ClassFile::from_bytes(&mut cursor) {
            for attr in &class_file.attributes {
                if let Attribute::SourceFile {
                    source_file_index, ..
                } = attr
                {
                    if let Ok(source) = class_file.constant_pool.try_get_utf8(*source_file_index) {
                        if source == "CollapseLoader" {
                            found_marker = true;
                            break;
                        }
                    }
                }
                if let Attribute::Signature {
                    signature_index, ..
                } = attr
                {
                    if let Ok(sig) = class_file.constant_pool.try_get_utf8(*signature_index) {
                        if sig == fake_signature {
                            found_marker = true;
                            break;
                        }
                    }
                }
            }
            if found_marker {
                break;
            }
            for field in &class_file.fields {
                for fattr in &field.attributes {
                    if let Attribute::ConstantValue {
                        constant_value_index,
                        ..
                    } = fattr
                    {
                        if let Ok(s) = class_file.constant_pool.try_get_utf8(*constant_value_index)
                        {
                            if s == encoded_value {
                                found_marker = true;
                                break;
                            }
                        }
                    }
                }
                if found_marker {
                    break;
                }
            }
            if found_marker {
                break;
            }
        }
    }

    Ok(has_zip_sig && found_marker)
}
