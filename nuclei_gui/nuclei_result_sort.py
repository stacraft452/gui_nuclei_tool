# nuclei_result_sort.py
import re
from collections import defaultdict
from datetime import datetime

LEVEL_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

def parse_line(line):
    """
    解析一行，返回 (level, type, content)
    """
    m = re.match(r'(?:\[[^\]]+\] )?\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.+)', line)
    if m:
        _name, info_type, level, content = m.groups()
        return level.lower(), info_type.lower(), line.strip()
    return 'unknown', 'unknown', line.strip()

def sort_nuclei_result(input_file, output_file=None):
    try:
        with open(input_file, encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        return False, f"读取文件失败: {e}"

    result = defaultdict(lambda: defaultdict(list))
    for line in lines:
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        level, info_type, content = parse_line(line)
        result[level][info_type].append(content)

    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"nuclei_results_sorted_{timestamp}.txt"

    with open(output_file, "w", encoding="utf-8") as f:
        idx = 1
        for level in LEVEL_ORDER:
            if level not in result:
                continue
            f.write(f"\n{'='*10} {level.upper()} {'='*10}\n")
            for info_type in sorted(result[level].keys()):
                f.write(f"\n--- [{info_type}] ---\n")
                for item in result[level][info_type]:
                    f.write(f"[{idx}] {item}\n")
                    idx += 1
    return True, output_file
