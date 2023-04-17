FROM ubuntu:22.04@sha256:67211c14fa74f070d27cc59d69a7fa9aeff8e28ea118ef3babc295a0428a6d21 as ctf

RUN apt-get update && \
    apt install -y software-properties-common

RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.10 python3.10-dev python3.10-distutils git libssl-dev libffi-dev build-essential tmux curl ruby-full

RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10 && \
    python3.10 -m pip install --upgrade pip && \
    python3.10 -m pip install --upgrade pwntools && \
    gem install one_gadget

RUN useradd -m ctf

WORKDIR /home/ctf

RUN git clone https://github.com/scwuaptx/Pwngdb.git /home/ctf/.config/Pwngdb && \
    cp /home/ctf/.config/Pwngdb/.gdbinit /home/ctf/.config/.gdbinit

RUN git clone https://github.com/pwndbg/pwndbg /home/ctf/.config/pwndbg && \
    cd /home/ctf/.config/pwndbg && \
    ./setup.sh


RUN echo -e '\
    source ~/.config/pwngdb/gdbinit.py\n\
    source ~/.config/Pwngdb/pwngdb.py\n\
    source ~/.config/Pwngdb/angelheap/gdbinit.py\n\
    set sysroot\n\
    define hook-run\n\
    python\n\
    import angelheap\n\
    angelheap.init_angelheap()\n\
    end\n\
    end\' >  /home/ctf/.gdbinit