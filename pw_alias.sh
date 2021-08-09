alias pw_unlock="stty -echo; read -r PW_MASTER; stty echo; export PW_MASTER"
alias pw_lock="unset PW_MASTER"
