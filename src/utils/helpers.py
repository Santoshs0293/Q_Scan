#helpers.py
import math
import os

def setup_logger(name="QSecureScan"):
    import logging
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

def calculate_entropy(file_path):
    logger = setup_logger()
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            logger.warning(f"Empty file: {file_path}")
            return None
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0
        for count in byte_counts:
            if count:
                prob = count / len(data)
                entropy -= prob * math.log2(prob)
        return entropy
    except PermissionError:
        logger.warning(f"Permission denied for {file_path}, skipping")
        return None
    except Exception as e:
        logger.warning(f"Failed to calculate entropy for {file_path}: {e}")
        return None