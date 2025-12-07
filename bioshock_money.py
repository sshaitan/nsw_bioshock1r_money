#!/usr/bin/env python3
import sys
import struct
import zlib
from pathlib import Path


HEADER_SIZE = 0x44
MONEY_SIG = b"\x29\x00\x00\x00\x00\x22\x6E\x00\x00\x00"  # хвост после денег


def parse_blocks(comp: bytes):
    """
    Разобрать хвост на список блоков:
    возвращает список (offset_в_хвосте, compressed_len, decompressed_len)
    """
    blocks = []
    offset = 0
    while offset < len(comp):
        if comp[offset:offset + 2] != b"\x78\x9C":
            # дальше уже не zlib — выходим
            break

        obj = zlib.decompressobj()
        dec = obj.decompress(comp[offset:])
        consumed = len(comp[offset:]) - len(obj.unused_data)
        blocks.append((offset, consumed, len(dec)))

        if not obj.unused_data:
            # больше блоков нет
            offset += consumed
            break

        extra = obj.unused_data
        if len(extra) < 4:
            break

        # первые 4 байта после потока — размер следующего блока
        size_next = struct.unpack("<I", extra[:4])[0]
        offset = offset + consumed + 4

    return blocks


def read_comp_blocks(comp: bytes, blocks):
    """
    По списку блоков достаём сами zlib-байты
    и проверяем, что размеры между блоками совпадают.
    """
    comp_blocks = []
    ptr = 0
    for i, (off, clen, dlen) in enumerate(blocks):
        if off != ptr:
            raise RuntimeError(f"desync: ожидали offset={ptr}, а получили {off}")
        comp_blocks.append(comp[ptr:ptr + clen])
        ptr += clen
        if i < len(blocks) - 1:
            size_next = struct.unpack("<I", comp[ptr:ptr + 4])[0]
            expected = blocks[i + 1][1]
            if size_next != expected:
                raise RuntimeError(
                    f"несовпадение размера блока {i+1}: в шве {size_next}, по факту {expected}"
                )
            ptr += 4
    return comp_blocks


def patch_money(original_bytes: bytes, new_money: int):
    header = bytearray(original_bytes[:HEADER_SIZE])
    comp = original_bytes[HEADER_SIZE:]

    # разбор блоков
    blocks = parse_blocks(comp)
    if not blocks:
        raise RuntimeError("не удалось распарсить zlib-блоки")

    comp_blocks = read_comp_blocks(comp, blocks)

    found_block_indices = []
    current_values = []
    new_comp_blocks = []

    for i, raw in enumerate(comp_blocks):
        dec = zlib.decompress(raw)
        idx = dec.find(MONEY_SIG)
        if idx >= 4:
            # нашли сигнатуру, читаем деньги
            cur_money = struct.unpack("<I", dec[idx - 4:idx])[0]
            current_values.append(cur_money)
            found_block_indices.append(i)

            # патчим на новое значение
            dec = dec[:idx - 4] + struct.pack("<I", new_money) + dec[idx:]
            raw = zlib.compress(dec)

        new_comp_blocks.append(raw)

    if not found_block_indices:
        raise RuntimeError("не нашли сигнатуру денег ни в одном блоке")

    # собираем новый хвост: блок_i + размер следующего блока
    comp_new = bytearray()
    for i, raw in enumerate(new_comp_blocks):
        comp_new += raw
        if i < len(new_comp_blocks) - 1:
            comp_new += struct.pack("<I", len(new_comp_blocks[i + 1]))

    # в заголовке по смещению 0x40 лежит размер первого блока
    first_block_size = len(new_comp_blocks[0])
    header[0x40:0x44] = struct.pack("<I", first_block_size)

    new_bytes = bytes(header) + bytes(comp_new)
    return new_bytes, found_block_indices, current_values


def main():
    if len(sys.argv) < 3:
        print(f"Использование: {sys.argv[0]} mainSave.bsg НОВОЕ_КОЛИЧЕСТВО_ДЕНЕГ [выходной_файл]")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    new_money = int(sys.argv[2])

    if len(sys.argv) >= 4:
        out_path = Path(sys.argv[3])
    else:
        out_path = in_path.with_name(in_path.stem + f"_money_{new_money}" + in_path.suffix)

    data = in_path.read_bytes()
    new_data, blocks_idx, cur_vals = patch_money(data, new_money)

    print(f"Нашёл деньги в блоках: {blocks_idx}")
    print(f"Текущие значения денег (по файлу): {cur_vals}")
    print(f"Ставлю новое значение денег: {new_money}")

    out_path.write_bytes(new_data)
    print(f"Готово, патч сохранён в: {out_path}")


if __name__ == "__main__":
    main()
