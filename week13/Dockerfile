FROM sagemath/sagemath:9.6

RUN sudo apt-get update -y && \
    sudo apt-get install -y libgmp3-dev libmpc-dev git && \
    git clone https://github.com/RsaCtfTool/RsaCtfTool.git

WORKDIR RsaCtfTool

RUN sage -sh -c 'pip install -r requirements.txt -r optional-requirements.txt'

ENTRYPOINT ["/home/sage/RsaCtfTool/RsaCtfTool.py"]