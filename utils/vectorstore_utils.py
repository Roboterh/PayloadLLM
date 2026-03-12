import os
import json
from uuid import uuid4
from loguru import logger
from langchain_community.embeddings import HuggingFaceBgeEmbeddings
from langchain_elasticsearch import ElasticsearchStore
from langchain_community.document_loaders import JSONLoader
from langchain_core.tools import tool

def connection(index_name):
    # model_name = "BAAI/bge-large-en-v1.5"
    model_path = "/xxx/xxx/bge-large-en-v1.5"
    model_kwargs = {'device': 'cpu'}
    encode_kwargs = {'normalize_embeddings': True} # set True to compute cosine similarity
    embeddings = HuggingFaceBgeEmbeddings(
        model_name=model_path,
        model_kwargs=model_kwargs,
        encode_kwargs=encode_kwargs,
    )
    
    elastic_vector_search = ElasticsearchStore(
        es_url="http://xxx:9200",
        index_name=index_name,
        embedding=embeddings,
    )
    return elastic_vector_search

def metadata_func(record: dict, metadata: dict) -> dict:
    metadata["payload"] = record.get("payload")
    
    return metadata

def save_to_vectorstore(payload_file, elastic_vector_search, index_name):
    if not os.path.exists(payload_file):
        logger.error("The file {} does not exist".format(payload_file))
        exit(1)
    if index_name == "payload_summary_index_test" or index_name == "xss_payload_summary_index_test" or index_name == "xxe_payload_summary_index_test":
        loader = JSONLoader(
            file_path=payload_file,
            jq_schema=".[]",
            content_key="summary",
            metadata_func=metadata_func,
        )
    elif index_name == "payload_index_test" or index_name == "xss_payload_index_test" or index_name == "xxe_payload_index_test":
        loader = JSONLoader(
            file_path=payload_file,
            jq_schema=".[]",
            content_key="payload",
        )
    docs = loader.load()
    logger.info("Indexing {} documents to vector store...".format(len(docs)))
    uuids = [str(uuid4()) for _ in range(len(docs))]
    # save the payload-summary pair to the vector store
    elastic_vector_search.add_documents(documents=docs, ids=uuids)
    
    
if __name__ == '__main__':
    loader = JSONLoader(
        file_path="datasets/sql-injection_summary.json",
        jq_schema=".[]",
        content_key="summary",
        metadata_func=metadata_func,
    )
    
    docs = loader.load()
    print(docs[0])