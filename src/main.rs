use arboard::Clipboard;
use fdpm::{SALT, copy_and_clear_pass, get_argon2, get_pass_from_rng};
use rand::SeedableRng;
use rand::{Rng, rngs::StdRng};
use std::io::Write;
use std::{env, io};
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //locks pages to ram only and opts out of debugging.
    //both calls are linux specific.
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            Err("couldn't set process as non dumpable (call to prctl failed)")?;
        }
        if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
            eprintln!("couldn't opt out of using swap (call to mlockall failed)");
            eprint!("want to proceed? [Y/n]");
            std::io::stderr().flush()?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y") {
                Err("refused to proceed.")?;
            }
        }
    };
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 && matches!(args[1].as_str(), "-h" | "--help") {
        print_help(&args[0]);
        return Ok(());
    }
    println!("input pass (won't be echoed)");
    let mut pass = rpassword::prompt_password(">")?;
    let argon2 = get_argon2();
    let mut seed = [0u8; 32];
    argon2
        .hash_password_into(pass.as_bytes(), SALT, &mut seed)
        .expect("couldn't hash master password.");
    pass.zeroize();
    let mut rng = <StdRng as SeedableRng>::from_seed(seed);
    seed.zeroize();

    //verify string is how I choose to solve the problem of inputting wrong password and not ever knowing its only 4 letters so pretty easy to remember
    //this allows for verifying your password is correct while
    let verify_string = get_pass_from_rng(&mut rng, Some(4))?;
    println!("your verify string is:{}", verify_string);
    println!("if this looks correct press enter if not input anything else.");
    let mut ok = String::new();
    io::stdin().read_line(&mut ok)?;
    if ok != "\n" {
        //why rewrite first 40 lines?
        #[allow(clippy::main_recursion)]
        main()?;
        return Ok(());
    }
    // if argv1 is none or cli arg ask user for desired service.
    let mut service = if args.get(1).is_none() || matches!(args[1].as_str(), "-l" | "--loop") {
        let mut service = String::new();
        println!("input desired service");
        io::stdin().read_line(&mut service)?;
        service
    } else {
        println!("using service name from cli argument.\n");
        args[1].clone()
    };

    // clear and overwrite clipboard to make sure password content is gone before exiting.
    ctrlc::set_handler(move || {
        let mut clip = Clipboard::new().expect("couldn't get handle to clear clipboard..");
        clip.set_text(" ").expect("couldn't overwrite clipboard");
        clip.clear().expect("couldn't clean clipboard..");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let mut clipboard = Clipboard::new()?;
    let mut pass_seed = [0u8; 32];
    rng.fill_bytes(&mut pass_seed);

    if args.len() >= 2 && matches!(args[1].as_str(), "-l" | "--loop") {
        println!("\n    NOTE: press ctrl+c whenever done.\n");
        copy_and_clear_pass(&service, &mut clipboard, &mut pass_seed)?;
        loop {
            println!("\ninput other service");
            let mut service = String::new();
            io::stdin().read_line(&mut service)?;
            copy_and_clear_pass(&service, &mut clipboard, &mut pass_seed)?;
            service.zeroize();
        }
    } else {
        copy_and_clear_pass(&service, &mut clipboard, &mut pass_seed)?;
        service.zeroize();
    };
    Ok(())
}
fn print_help(program_name: &str) {
    println!("fully deterministic password manager (fdpm):");
    println!("  takes a password and runs it trough a cryptographically secure RNG.");
    println!(
        "  fully deterministically generating passwords, that never touch non volatile in ANY form."
    );
    println!(
        "  mixes both master password AND service your service name to generate each individual password"
    );
    println!(
        "  stores ZERO metadata at all, so you must provide both master password and service name each time"
    );
    println!(
        "  this password manger supports plausible deniability. since this password manager leaves no traces at all."
    );
    println!(
        "  after this programs closes, nothing on the system (other the binary itself) points to you ever had of your passwords on this system"
    );
    println!(
        "  allowing for use in any computer on earth (even fully airgaped ones) no vault sharing required  just needs the binary.."
    );
    println!("USAGE:");
    println!("  {program_name} -h | --help    prints this message");
    println!(
        "  {program_name} <service>      pass on service name as a shell argument (possibly leaks service name to shell history make sure to prefix command by space to prevent it). ",
    );
    println!(
        "  {program_name} -l | --loop    loops instead of exiting useful when migrating stuff over (you must generate entirely new passwords)"
    )
}
