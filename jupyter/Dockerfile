FROM quay.io/jupyter/datascience-notebook:ubuntu-24.04
###########################################################
#
# LABEL Mandatory for the Pipeline - DO NOT DELETE
#
###########################################################
LABEL name=jupiter \
      authors=op \
      version=v0.01
###########################################################
#
# ENV Mandatory for the Pipeline - DO NOT DELETE
#
###########################################################

USER jovyan

#COPY requirements.txt  /requirements.txt
# not used to speed up image build thanks to layer caching
# just add new install line a the end of the file

RUN set -ex \
  && pip install pip==24.0
#  && pip3 install --no-cache-dir -r /requirements.txt
#
RUN pip3 install --no-cache-dir transformers
RUN pip3 install --no-cache-dir numpy
RUN pip3 install --no-cache-dir torch
RUN pip3 install --no-cache-dir tensorflow
#
RUN pip3 install --no-cache-dir neo4j
RUN pip3 install --no-cache-dir neo4j_graphrag
#
RUN pip3 install --no-cache-dir tf-keras
RUN pip3 install --no-cache-dir sentence-transformers
RUN pip3 install --no-cache-dir pdfminer
RUN pip3 install --no-cache-dir pdfminer.six
RUN pip3 install --no-cache-dir markdownify
RUN pip3 install --no-cache-dir typing
RUN pip3 install --no-cache-dir PyPDF2
#
RUN pip3 install --no-cache-dir langchain-community
RUN pip3 install --no-cache-dir langchain
RUN pip3 install --no-cache-dir langchainhub
RUN pip3 install --no-cache-dir langchain_core
RUN pip3 install --no-cache-dir langchain-ollama
RUN pip3 install --no-cache-dir langchain_openai
RUN pip3 install --no-cache-dir langchain_experimental
RUN pip3 install --no-cache-dir langchain_text_splitters 
#
RUN pip3 install --no-cache-dir llama-index
RUN pip3 install --no-cache-dir llama-index-vector-stores-neo4jvector
#
RUN pip3 install --no-cache-dir requests
RUN pip3 install --no-cache-dir circuitbreaker
RUN pip3 install --no-cache-dir xmltodict
RUN pip3 install --no-cache-dir spacy
RUN pip3 install --no-cache-dir networkx
RUN pip3 install --no-cache-dir rdflib
RUN pip3 install --no-cache-dir python-dotenv
RUN pip3 install --no-cache-dir tiktoken
RUN pip3 install --no-cache-dir langchain-openai
RUN pip3 install --no-cache-dir seaborn
RUN pip3 install --no-cache-dir tqdm
RUN pip3 install --no-cache-dir pandas
#
RUN python -m spacy download en_core_web_sm
#
RUN pip install git+https://github.com/explodinggradients/ragas
#
RUN pip install bash_kernel
RUN python -m bash_kernel.install
RUN pip3 install --no-cache-dir langfuse 
RUN python -m spacy download en_core_web_md
RUN python -m spacy download en_core_web_lg
RUN pip3 install --no-cache-dir matplotlib
RUN pip3 install --no-cache-dir ipywidgets
RUN pip3 install --no-cache-dir jupyterlab notebook ipywidgets jupyterlab_widgets
#
USER root
#
#RUN apt-get update \
#  && apt-get -y upgrade
#RUN apt-get install -y poppler-utils libpoppler-dev 
#RUN rm -rf /var/cache/apt/archives /var/lib/apt/lists/*.
#RUN pip3 install --no-cache-dir python-poppler deepdoctection gptparse
RUN pip3 install --no-cache-dir scikit-learn
RUN pip3 install --no-cache-dir pyvis
RUN pip3 install --no-cache-dir plotly
RUN pip3 install pymupdf
#
USER jovyan