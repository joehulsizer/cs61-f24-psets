#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

int run_conditional(shell_parser conditional);
int run_pipeline(shell_parser pipeline);
void reap_zombies();
// struct command
//    Data structure describing a command. Add your own stuff.

struct command {
    std::vector<std::string> args;
    pid_t pid = -1;      // process ID running this command, -1 if none
    int status = 0;
    int input_fd = STDIN_FILENO;
    int output_fd = STDOUT_FILENO;
    int error_fd = STDERR_FILENO;
    int pipe_read_fd = -1;
    int pipe_write_fd = -1;
    command()= default;
    ~command() {
        if (input_fd != STDIN_FILENO) {
            close(input_fd);
            input_fd = STDIN_FILENO;
        }
        if (output_fd != STDOUT_FILENO) {
            close(output_fd);
            output_fd = STDOUT_FILENO;
        }
        if (error_fd != STDERR_FILENO) {
            close(error_fd);
            error_fd = STDERR_FILENO;
        }
    };

    int run() {
        if (args.empty()) return 1;
        int saved_stdin = -1, saved_stdout = -1, saved_stderr = -1;
        if (input_fd != STDIN_FILENO) {
            saved_stdin = dup(STDIN_FILENO);
            dup2(input_fd, STDIN_FILENO);
            close(input_fd);
            input_fd = STDIN_FILENO;
        }
        if (output_fd != STDOUT_FILENO) {
            saved_stdout = dup(STDOUT_FILENO);
            dup2(output_fd, STDOUT_FILENO);
            close(output_fd);
            output_fd = STDOUT_FILENO;
        }
        if (error_fd != STDERR_FILENO) {
            saved_stderr = dup(STDERR_FILENO);
            dup2(error_fd, STDERR_FILENO);
            close(error_fd);
            error_fd = STDERR_FILENO;
        }
        if (args[0] == "cd") {
            const char* dir = args.size() > 1 ? args[1].c_str() : getenv("HOME");
            if (!dir) {
                fprintf(stderr, "cd: HOME not set\n");
                this->status = 1;
            } else if (chdir(dir) == -1) {
                fprintf(stderr, "cd: %s: %s\n", dir, strerror(errno));
                this->status = 1;
            } else {
                this->status = 0;
            }
            if (saved_stdin != -1) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            if (saved_stdout != -1) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            if (saved_stderr != -1) {
                dup2(saved_stderr, STDERR_FILENO);
                close(saved_stderr);
            }

            this->pid = 0;
            return this->status;
        }
        pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }

        if (pid == 0) {
            if (input_fd != STDIN_FILENO) {
                dup2(input_fd, STDIN_FILENO);
                close(input_fd);
            } else if (pipe_read_fd != -1) {
                dup2(pipe_read_fd, STDIN_FILENO);
                close(pipe_read_fd);
            }
            if (output_fd != STDOUT_FILENO) {
                dup2(output_fd, STDOUT_FILENO);
                close(output_fd);
            } else if (pipe_write_fd != -1) {
                dup2(pipe_write_fd, STDOUT_FILENO);
                close(pipe_write_fd);
            }
            if (error_fd != STDERR_FILENO) {
                dup2(error_fd, STDERR_FILENO);
                close(error_fd);
            }
            std::vector<char*> c_args;
            for (const auto& arg : args) {
                c_args.push_back(const_cast<char*>(arg.c_str()));
            }
            c_args.push_back(nullptr);

            execvp(c_args[0], c_args.data());
            fprintf(stderr, "%s: command not found\n", c_args[0]);
            _exit(1);
        } else {
            this->pid = pid;
            if (pipe_read_fd != -1) {
                close(pipe_read_fd);
                pipe_read_fd = -1;
            }
            if (pipe_write_fd != -1) {
                close(pipe_write_fd);
                pipe_write_fd = -1;
            }
            if (saved_stdin != -1) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            if (saved_stdout != -1) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            if (saved_stderr != -1) {
                dup2(saved_stderr, STDERR_FILENO);
                close(saved_stderr);
            }
        }
        return 0;
    }
};

int run_conditional(shell_parser conditional) {
    int last_status = 0;
    shell_parser pipeline = conditional.first_pipeline();
    int prev_operator = TYPE_SEQUENCE;

    while (pipeline) {
        int next_operator = pipeline.op();
        bool should_run = true;

        if (prev_operator == TYPE_AND && last_status != 0) {
            should_run = false;
        } else if (prev_operator == TYPE_OR && last_status == 0) {
            should_run = false;
        }

        if (should_run) {
            last_status = run_pipeline(pipeline);
        }

        prev_operator = next_operator;
        pipeline.next_pipeline();
    }

    return last_status;
}
int run_pipeline(shell_parser pipeline) {
    int last_status = 0;
    std::vector<command*> commands;
    shell_parser cmd_parser = pipeline.first_command();
    while (cmd_parser) {
        command* cmd = new command();

        auto token = cmd_parser.first_token();
        while (token) {
            if (token.type() == TYPE_NORMAL) {
                cmd->args.push_back(token.str());
            } else if (token.type() == TYPE_REDIRECT_OP) {
                std::string op = token.str();
                token.next();
                if (!token || token.type() != TYPE_NORMAL) {
                    fprintf(stderr, "Syntax error: missing filename after redirection\n");
                    last_status = 1;
                    delete cmd;
                    for (auto c : commands) delete c;
                    return last_status;
                }

                std::string filename = token.str();
                int fd = -1;

                if (op == "<") {
                    fd = open(filename.c_str(), O_RDONLY);
                    if (fd == -1) {
                        fprintf(stderr, "%s: %s\n", filename.c_str(), strerror(errno));
                        last_status = 1;
                        delete cmd;
                        for (auto c : commands) delete c;
                        return last_status;
                    }
                    cmd->input_fd = fd;
                } else if (op == ">") {
                    fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
                    if (fd == -1) {
                        fprintf(stderr, "%s: %s\n", filename.c_str(), strerror(errno));
                        last_status = 1;
                        delete cmd;
                        for (auto c : commands) delete c;
                        return last_status;
                    }
                    cmd->output_fd = fd;
                } else if (op == "2>") {
                    fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
                    if (fd == -1) {
                        fprintf(stderr, "%s: %s\n", filename.c_str(), strerror(errno));
                        last_status = 1;
                        delete cmd;
                        for (auto c : commands) delete c;
                        return last_status;
                    }
                    cmd->error_fd = fd;
                }
            }
            token.next();
        }

        commands.push_back(cmd);
        cmd_parser.next_command();
    }

    if (commands.empty()) {
        return 0;
    }
    for (size_t i = 0; i < commands.size() - 1; ++i) {
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            perror("pipe");
            for (auto c : commands) delete c;
            return 1;
        }
        commands[i]->pipe_write_fd = pipefd[1];
        commands[i + 1]->pipe_read_fd = pipefd[0];
    }
    for (auto cmd : commands) {
        if (cmd->input_fd != STDIN_FILENO) {
            if (cmd->pipe_read_fd != -1) {
                close(cmd->pipe_read_fd);
                cmd->pipe_read_fd = -1;
            }
        }
        cmd->run();
    }
    for (auto cmd : commands) {
        if (cmd->pipe_read_fd != -1) {
            close(cmd->pipe_read_fd);
            cmd->pipe_read_fd = -1;
        }
        if (cmd->pipe_write_fd != -1) {
            close(cmd->pipe_write_fd);
            cmd->pipe_write_fd = -1;
        }
    }
    int status = 0;
    for (auto cmd : commands) {
        if (cmd->pid > 0) {
            int cmd_status;
            waitpid(cmd->pid, &cmd_status, 0);
            if (cmd == commands.back()) {
                status = WIFEXITED(cmd_status) ? WEXITSTATUS(cmd_status) : 1;
            }
        } else {
            status = cmd->status;
        }
    }
    for (auto cmd : commands) {
        delete cmd;
    }

    return status;
}
void run_list(shell_parser parser) {
    shell_parser conditional = parser.first_conditional();

    while (conditional) {
        bool is_background = (conditional.op() == TYPE_BACKGROUND);

        if (is_background) {
            pid_t bg_pid = fork();
            if (bg_pid < 0) {
                perror("fork");
                return;
            }
            if (bg_pid == 0) {
                setpgid(0, 0);
                 _exit(run_conditional(conditional));
            }
        } else {
            run_conditional(conditional);
        }

        conditional.next_conditional();
    }
}
void reap_zombies() {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        }
}


// command::command()
//    This constructor function initializes a `command` structure. You may
//    add stuff to it as you grow the command structure.



// command::~command()
//    This destructor function is called to delete a command.


// COMMAND EXECUTION

// command::run()
//    Creates a single child process running the command in `this`, and
//    sets `this->pid` to the pid of the child process.
//
//    If a child process cannot be created, this function should call
//    `_exit(EXIT_FAILURE)` (that is, `_exit(1)`) to exit the containing
//    shell or subshell. If this function returns to its caller,
//    `this->pid > 0` must always hold.
//
//    Note that this function must return to its caller *only* in the parent
//    process. The code that runs in the child process must `execvp` and/or
//    `_exit`.
//
//    PHASE 1: Fork a child process and run the command using `execvp`.
//       This will require creating a vector of `char*` arguments using
//       `this->args[N].c_str()`. Note that the last element of the vector
//       must be a `nullptr`.
//    PHASE 4: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PHASE 7: Handle redirections.


// run_list(c)
//    Run the command *list* contained in `section`.
//
//    PHASE 1: Use `waitpid` to wait for the command started by `c->run()`
//        to finish.
//
//    The remaining phases may require that you introduce helper functions
//    (e.g., to process a pipeline), write code in `command::run`, and/or
//    change `struct command`.
//
//    It is possible, and not too ugly, to handle lists, conditionals,
//    *and* pipelines entirely within `run_list`, but in general it is clearer
//    to introduce `run_conditional` and `run_pipeline` functions that
//    are called by `run_list`. It’s up to you.
//
//    PHASE 2: Introduce a loop to run a list of commands, waiting for each
//       to finish before going on to the next.
//    PHASE 3: Change the loop to handle conditional chains.
//    PHASE 4: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PHASE 5: Change the loop to handle background conditional chains.
//       This may require adding another call to `fork()`!


int main(int argc, char* argv[]) {
    FILE* command_file = stdin;
    bool quiet = false;

    // Check for `-q` option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        quiet = true;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) {
        command_file = fopen(argv[1], "rb");
        if (!command_file) {
            perror(argv[1]);
            return 1;
        }
    }

    // - Put the shell into the foreground
    // - Ignore the SIGTTOU signal, which is sent when the shell is put back
    //   into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file)) {
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) {
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = false;
        }
        reap_zombies();

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == nullptr) {
            if (ferror(command_file) && errno == EINTR) {
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } else {
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) {
            run_list(shell_parser(buf));
            bufpos = 0;
            needprompt = true;
        }

        // Handle zombie processes and/or interrupt requests
        // Your code here!
    }
        reap_zombies();

    return 0;
}