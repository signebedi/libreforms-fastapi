import os, logging


def set_logger(environment, log_file_name, namespace, log_directory=os.path.join(os.getcwd(), 'instance', 'log'), write_to_file:bool=True):
    logger = logging.getLogger(namespace)
    logger.setLevel(logging.INFO)

    # if environment == "production":
    if write_to_file and environment != "testing":
        os.makedirs(log_directory, exist_ok=True)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        log_file = os.path.join(log_directory, environment+"_"+log_file_name)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=10485760,
            backupCount=20,
            encoding='utf-8', 
            mode='a'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger