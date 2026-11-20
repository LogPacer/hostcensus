//! What an interpreter or a language runtime is running.
//!
//! `/usr/bin/java` or `/usr/bin/python3` says little about a process. The
//! script, jar, module or class it was started with says what it is. That one
//! argument is picked out of the command line; every other argument is left
//! behind, because arguments can hold secrets.

/// What an argument has to look like before it is taken for a program.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A path to a file that exists, or that ends in one of the
    /// interpreter's extensions.
    File,
    /// A module or class name: `http.server`, `com.example.Main`.
    DottedName,
}

struct Interpreter {
    /// Options followed by a value that is not the program.
    takes_a_value: &'static [&'static str],
    /// Options that put the program on the command line itself, or mean
    /// there is none.
    ends_the_search: &'static [&'static str],
    /// Options followed by the program.
    names_the_program: &'static [(&'static str, Shape)],
    /// Words between the interpreter and the program, as in `deno run`.
    subcommands: &'static [&'static str],
    /// The shape of a program given as a bare argument.
    bare: Shape,
    extensions: &'static [&'static str],
}

const JAVA: Interpreter = Interpreter {
    takes_a_value: &[
        "-cp",
        "-classpath",
        "--class-path",
        "-p",
        "--module-path",
        "--upgrade-module-path",
        "--add-modules",
        "--add-opens",
        "--add-exports",
        "--add-reads",
        "--patch-module",
    ],
    ends_the_search: &[],
    names_the_program: &[
        ("-jar", Shape::File),
        ("-m", Shape::DottedName),
        ("--module", Shape::DottedName),
    ],
    subcommands: &[],
    bare: Shape::DottedName,
    extensions: &["jar", "war"],
};

const PYTHON: Interpreter = Interpreter {
    takes_a_value: &["-W", "-X", "--check-hash-based-pycs"],
    ends_the_search: &["-c"],
    names_the_program: &[("-m", Shape::DottedName)],
    subcommands: &[],
    bare: Shape::File,
    extensions: &["py", "pyz", "pyc"],
};

const NODE: Interpreter = Interpreter {
    takes_a_value: &[
        "-r",
        "--require",
        "--loader",
        "--experimental-loader",
        "--import",
    ],
    ends_the_search: &["-e", "--eval", "-p", "--print"],
    names_the_program: &[],
    subcommands: &["run"],
    bare: Shape::File,
    extensions: &["js", "mjs", "cjs", "ts", "mts"],
};

const RUBY: Interpreter = Interpreter {
    takes_a_value: &["-I", "-r", "-C", "-E"],
    ends_the_search: &["-e"],
    names_the_program: &[],
    subcommands: &[],
    bare: Shape::File,
    extensions: &["rb", "ru"],
};

const PHP: Interpreter = Interpreter {
    takes_a_value: &["-c", "-d", "-S", "-t", "-z"],
    ends_the_search: &["-r", "-R", "-B", "-E"],
    names_the_program: &[("-f", Shape::File)],
    subcommands: &[],
    bare: Shape::File,
    extensions: &["php", "phar"],
};

const PERL: Interpreter = Interpreter {
    takes_a_value: &["-I"],
    ends_the_search: &["-e", "-E"],
    names_the_program: &[],
    subcommands: &[],
    bare: Shape::File,
    extensions: &["pl", "pm", "psgi"],
};

const DOTNET: Interpreter = Interpreter {
    takes_a_value: &[],
    ends_the_search: &[],
    names_the_program: &[],
    subcommands: &["exec"],
    bare: Shape::File,
    extensions: &["dll"],
};

const SHELL: Interpreter = Interpreter {
    takes_a_value: &["-o", "+o", "--rcfile", "--init-file"],
    ends_the_search: &["-c"],
    names_the_program: &[],
    subcommands: &[],
    bare: Shape::File,
    extensions: &["sh", "bash"],
};

fn interpreter(executable: &str) -> Option<&'static Interpreter> {
    let name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    // `python3.12`, `ruby3.3` and `php8.3` are the same interpreters as
    // `python`, `ruby` and `php`.
    let name = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    Some(match name {
        "java" => &JAVA,
        "python" => &PYTHON,
        "node" | "nodejs" | "deno" | "bun" => &NODE,
        "ruby" => &RUBY,
        "php" => &PHP,
        "perl" => &PERL,
        "dotnet" => &DOTNET,
        "sh" | "bash" | "dash" | "zsh" | "ksh" => &SHELL,
        _ => return None,
    })
}

/// The script, jar, module or class that `executable` runs, read from the
/// arguments it was started with (`arguments[0]` is the executable itself).
/// `is_file` says whether a path names an existing file, as seen from the
/// process.
///
/// Nothing is returned unless the executable is a known interpreter and the
/// argument has the shape of a program, so a value that merely sits where a
/// program could be is not taken for one.
pub(crate) fn of(
    executable: &str,
    arguments: &[String],
    is_file: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let interpreter = interpreter(executable)?;
    let mut arguments = arguments.iter().skip(1).map(String::as_str);

    while let Some(argument) = arguments.next() {
        if interpreter.ends_the_search.contains(&argument) {
            return None;
        }
        if let Some((_, shape)) = interpreter
            .names_the_program
            .iter()
            .find(|(option, _)| *option == argument)
        {
            return program(arguments.next()?, *shape, interpreter, is_file);
        }
        if interpreter.takes_a_value.contains(&argument) {
            arguments.next();
            continue;
        }
        if argument.starts_with('-') || interpreter.subcommands.contains(&argument) {
            continue;
        }
        // The first bare argument is the program or nothing is: what follows
        // it are the program's own arguments.
        return program(argument, interpreter.bare, interpreter, is_file);
    }
    None
}

fn program(
    argument: &str,
    shape: Shape,
    interpreter: &Interpreter,
    is_file: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let fits = match shape {
        Shape::DottedName => is_dotted_name(argument),
        Shape::File => {
            is_plain_path(argument)
                && (has_extension(argument, interpreter.extensions) || is_file(argument))
        }
    };
    fits.then(|| argument.to_string())
}

fn has_extension(path: &str, extensions: &[&str]) -> bool {
    path.rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && extensions.contains(&extension))
}

/// Letters, digits and `. _ / @ + -`: a path, and nothing that could be an
/// address, an assignment or free text.
fn is_plain_path(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 256
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/@+-".contains(&byte))
}

fn is_dotted_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 256
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_' || first == b'$')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_$.".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nothing_exists(_: &str) -> bool {
        false
    }

    fn run(command_line: &str) -> Option<String> {
        run_where(command_line, &nothing_exists)
    }

    fn run_where(command_line: &str, is_file: &dyn Fn(&str) -> bool) -> Option<String> {
        let arguments: Vec<String> = command_line.split(' ').map(String::from).collect();
        of(&arguments[0], &arguments, is_file)
    }

    #[test]
    fn a_jvm_names_its_jar_module_or_main_class() {
        for (command_line, program) in [
            (
                "java -jar /opt/shop/shop.jar --server.port=8080",
                "/opt/shop/shop.jar",
            ),
            (
                "/usr/lib/jvm/java-21/bin/java -Xmx2g -Dkey=secret -jar app.war",
                "app.war",
            ),
            (
                "java -cp /opt/app/lib/* com.example.Main --token abc",
                "com.example.Main",
            ),
            (
                "java -classpath a.jar:b.jar -Dx=y org.apache.catalina.startup.Bootstrap start",
                "org.apache.catalina.startup.Bootstrap",
            ),
            (
                "java --module-path mods -m shop.app/com.example.Main",
                "none",
            ),
            ("java --module-path mods --module shop.app", "shop.app"),
            ("java -version", "none"),
            ("java -jar not-a-jar --x", "none"),
        ] {
            assert_eq!(
                run(command_line).as_deref().unwrap_or("none"),
                program,
                "{command_line}"
            );
        }
    }

    #[test]
    fn a_script_interpreter_names_its_script_or_module() {
        for (command_line, program) in [
            (
                "python3 /srv/app/manage.py runserver 0.0.0.0:8000",
                "/srv/app/manage.py",
            ),
            (
                "/usr/bin/python3.12 -u -m gunicorn shop.wsgi --bind :8000",
                "gunicorn",
            ),
            ("python -W ignore -X dev worker.py", "worker.py"),
            ("python3 -c import_os;print(1)", "none"),
            ("node /app/server.js --port 3000", "/app/server.js"),
            (
                "node --require ./tracing.js --max-old-space-size=4096 dist/main.mjs",
                "dist/main.mjs",
            ),
            ("deno run --allow-net main.ts", "main.ts"),
            ("bun run index.ts", "index.ts"),
            ("node -e console.log(1)", "none"),
            ("ruby3.3 -I lib config.ru", "config.ru"),
            (
                "php8.3 -d memory_limit=1G artisan.php queue:work",
                "artisan.php",
            ),
            ("php -f /var/www/cron.php", "/var/www/cron.php"),
            (
                "perl /usr/local/bin/sync.pl --password hunter2",
                "/usr/local/bin/sync.pl",
            ),
            (
                "dotnet exec /app/Shop.dll --urls http://0.0.0.0:5000",
                "/app/Shop.dll",
            ),
            ("dotnet Shop.dll", "Shop.dll"),
            ("bash /opt/backup/run.sh daily", "/opt/backup/run.sh"),
            ("sh -c rsync_-a_/var/log_backup@host:", "none"),
        ] {
            assert_eq!(
                run(command_line).as_deref().unwrap_or("none"),
                program,
                "{command_line}"
            );
        }
    }

    #[test]
    fn a_script_without_an_extension_counts_only_when_the_file_exists() {
        let exists = |path: &str| path == "/usr/local/bin/puma" || path == "bin/rails";

        assert_eq!(
            run_where("ruby /usr/local/bin/puma -C config/puma.rb", &exists).as_deref(),
            Some("/usr/local/bin/puma")
        );
        assert_eq!(
            run_where("ruby bin/rails server", &exists).as_deref(),
            Some("bin/rails")
        );
        assert_eq!(run("ruby /usr/local/bin/puma -C config/puma.rb"), None);
    }

    #[test]
    fn a_value_that_sits_where_a_program_could_be_is_not_taken_for_one() {
        for command_line in [
            // An option this table does not know, followed by its value.
            "node --unknown-option a-secret-value server.js",
            "python3 --some-flag hunter2 app.py",
            // Addresses, assignments and free text are not paths.
            "node https://user:secret@example.net/app.js",
            "python3 KEY=value.py",
            "ruby postgres://shop:secret@db/shop.rb",
            "bash secret:value.sh",
        ] {
            assert_eq!(run(command_line), None, "{command_line}");
        }
    }

    #[test]
    fn only_interpreters_have_a_program() {
        for command_line in [
            "/usr/sbin/nginx -g daemon_off;",
            "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main",
            "sleep 30.py",
            "javac Main.java",
            "python-config --includes",
        ] {
            assert_eq!(run(command_line), None, "{command_line}");
        }
    }

    #[test]
    fn versioned_names_are_the_same_interpreter() {
        for executable in [
            "python3",
            "python3.12",
            "/usr/bin/python3.12",
            "ruby3.3",
            "php8.3",
        ] {
            assert!(interpreter(executable).is_some(), "{executable}");
        }
    }
}
