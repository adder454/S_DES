import random
import tkinter as tk
from tkinter import messagebox

# 初始置换（IP）表
IP = [2, 6, 3, 1, 4, 8, 5, 7]

# 逆初始置换（IP^-1）表
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

# 扩展（E）表
E = [4, 1, 2, 3, 2, 3, 4, 1]

# 置换（P4）表
P4 = [2, 4, 3, 1]

# S盒
S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 0, 2]]

S1 = [[0, 1, 2, 3],
      [2, 3, 1, 0],
      [3, 0, 1, 2],
      [2, 1, 0, 3]]

# 初始密钥（10位）到8位密钥的初始置换表
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

# 置换（P8）表（从10位到8位密钥）
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

# 密钥生成中的左循环移位（LS-1）
LS_1 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]

# 对8位数据进行初始置换（IP）
def initial_permutation(data):
    permuted_data = [data[ip - 1] for ip in IP]
    return permuted_data

# 对8位数据进行逆初始置换（IP^-1）
def inverse_initial_permutation(data):
    permuted_data = [data[ip - 1] for ip in IP_INV]
    return permuted_data

# 将4位数据扩展为8位数据（使用扩展表E）
def expand(data):
    expanded_data = [data[e - 1] for e in E]
    return expanded_data

# 对两个8位数据块进行异或运算
def xor(data1, data2):
    result = []
    for i in range(len(data1)):
        result.append(data1[i] ^ data2[i])
    return result

# 将一个8位数据块分成两个4位数据块
def split(data):
    return data[:4], data[4:]

# 使用S盒对4位数据块进行替代
def s_box(data, s_box_table):
    row = int(''.join(map(str, [data[0], data[3]])), 2)
    col = int(''.join(map(str, data[1:3])), 2)
    return [int(x) for x in format(s_box_table[row][col], '02b')]

# 使用给定的置换表对4位数据块进行置换
def permute(data, perm_table):
    return [data[p - 1] for p in perm_table]

# 从10位密钥生成轮密钥
def generate_round_keys(key):
    key = permute(key, P10)
    left, right = split(key)

    round_keys = []
    for i in range(2):
        left = left[LS_1[i]:] + left[:LS_1[i]]
        right = right[LS_1[i]:] + right[:LS_1[i]]
        round_key = permute(left + right, P8)
        round_keys.append(round_key)

    return round_keys

# 执行F函数（Feistel函数）
def feistel(data, sub_key):
    data = expand(data)
    data = xor(data, sub_key)
    left, right = split(data)
    left = s_box(left, S0)
    right = s_box(right, S1)
    data = permute(left + right, P4)
    return data

# 使用10位密钥加密8位明文
def encrypt(plaintext, key):
    round_keys = generate_round_keys(key)
    plaintext = initial_permutation(plaintext)
    left, right = split(plaintext)

    for i in range(2):
        left, right = right, xor(left, feistel(right, round_keys[i]))

    ciphertext = inverse_initial_permutation(right + left)
    return ciphertext

# 使用10位密钥解密8位密文
def decrypt(ciphertext, key):
    round_keys = generate_round_keys(key)
    ciphertext = initial_permutation(ciphertext)
    left, right = split(ciphertext)

    for i in range(2):
        left, right = right, xor(left, feistel(right, round_keys[1 - i]))

    plaintext = inverse_initial_permutation(right + left)
    return plaintext

# 将二进制字符串转换为整数列表
def binary_string_to_list(binary_string):
    return [int(bit) for bit in binary_string]

# 将整数列表转换为二进制字符串
def list_to_binary_string(data_list):
    return ''.join(map(str, data_list))

# 生成一个随机的10位密钥
def generate_random_key():
    return [random.randint(0, 1) for _ in range(10)]

# 将ASCII字符转换为8位的二进制字符串
def ascii_to_binary(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    return binary_text

# 将8位的二进制字符串转换为ASCII字符
def binary_to_ascii(binary_text):
    ascii_text = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
    return ascii_text

# 将ASCII编码的字符串分组成8位数据块，然后加密
def encrypt_ascii_text(ascii_text, key):
    binary_text = ascii_to_binary(ascii_text)
    encrypted_binary_text = ''

    for i in range(0, len(binary_text), 8):
        plaintext_block = list(map(int, binary_text[i:i+8]))
        ciphertext_block = encrypt(plaintext_block, key)
        encrypted_binary_text += ''.join(map(str, ciphertext_block))

    return binary_to_ascii(encrypted_binary_text)

# 将ASCII编码的字符串分组成8位数据块，然后解密
def decrypt_ascii_text(encrypted_ascii_text, key):
    encrypted_binary_text = ascii_to_binary(encrypted_ascii_text)
    decrypted_binary_text = ''

    for i in range(0, len(encrypted_binary_text), 8):
        ciphertext_block = list(map(int, encrypted_binary_text[i:i+8]))
        plaintext_block = decrypt(ciphertext_block, key)
        decrypted_binary_text += ''.join(map(str, plaintext_block))

    return binary_to_ascii(decrypted_binary_text)

def chinese_to_unicode_binary(text):
    binary_text = ''.join(format(ord(char), '016b') for char in text)
    return binary_text

# 将Unicode编码的二进制字符串转换为中文文本
def unicode_binary_to_chinese(binary_text):
    chinese_text = ''.join(chr(int(binary_text[i:i+16], 2)) for i in range(0, len(binary_text), 16))
    return chinese_text

# 将中文文本分组成8位数据块，然后加密
def encrypt_chinese_text(chinese_text, key):
    unicode_binary_text = chinese_to_unicode_binary(chinese_text)
    encrypted_binary_text = ''

    for i in range(0, len(unicode_binary_text), 8):
        plaintext_block = list(map(int, unicode_binary_text[i:i+8]))
        ciphertext_block = encrypt(plaintext_block, key)
        encrypted_binary_text += ''.join(map(str, ciphertext_block))

    return unicode_binary_to_chinese(encrypted_binary_text)

# 将中文文本分组成8位数据块，然后解密
def decrypt_chinese_text(encrypted_chinese_text, key):
    encrypted_binary_text = chinese_to_unicode_binary(encrypted_chinese_text)
    decrypted_binary_text = ''

    for i in range(0, len(encrypted_binary_text), 8):
        ciphertext_block = list(map(int, encrypted_binary_text[i:i+8]))
        plaintext_block = decrypt(ciphertext_block, key)
        decrypted_binary_text += ''.join(map(str, plaintext_block))

    return unicode_binary_to_chinese(decrypted_binary_text)

# 测试部分


# Tkinter GUI界面部分(unicode版)
def main():
    def encrypt_text():
        plaintext = input_text.get()
        key = key_entry.get()
        if not validate_binary(key):
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return
        key = list(map(int, key))
        if len(key) != 10:
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return

        ciphertext = encrypt_chinese_text(plaintext, key)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
        messagebox.showinfo("Encryption", "成功使用给定密钥加密明文")

    def decrypt_text():
        ciphertext = input_text.get()
        key = key_entry.get()
        if not validate_binary(key):
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return
        key = list(map(int, key))
        if len(key) != 10:
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return

        plaintext = decrypt_chinese_text(ciphertext, key)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)
        messagebox.showinfo("Decryption", "成功使用给定密钥解密密文")

    def validate_binary(binary_string):
        return all(bit in '01' for bit in binary_string)

    def random_key():
        messagebox.showinfo("随机密钥", generate_random_key())

    # 创建主窗口
    root = tk.Tk()
    root.title("S-DES 加解密GUI（unicode版）")

    # 设置GUI窗口大小
    root.geometry("600x400")

    # 创建标签和文本框用于输入明文/密文和密钥
    encrypt_button = tk.Button(root, text="随机生成密钥", command=random_key)
    encrypt_button.pack()
    input_label = tk.Label(root, text="输入明文或密文（支持中文）:")
    input_label.pack()
    input_text = tk.Entry(root)
    input_text.pack()

    key_label = tk.Label(root, text="密钥（10位二进制数）:")
    key_label.pack()
    key_entry = tk.Entry(root)
    key_entry.pack()

    # 创建加密和解密按钮
    encrypt_button = tk.Button(root, text="加密", command=encrypt_text)
    encrypt_button.pack()
    encrypt_button.pack()

    decrypt_button = tk.Button(root, text="解密", command=decrypt_text)
    decrypt_button.pack()

    # 创建文本框用于显示明文和密文
    plaintext_label = tk.Label(root, text="明文:")
    plaintext_label.pack()
    plaintext_entry = tk.Entry(root)
    plaintext_entry.pack()

    ciphertext_label = tk.Label(root, text="密文:")
    ciphertext_label.pack()
    ciphertext_entry = tk.Entry(root)
    ciphertext_entry.pack()

    # 启动主事件循环
    root.mainloop()

# Tkinter GUI界面部分(ASCII版)
def asc():
    def encrypt_text():
        plaintext = input_text.get()
        key = key_entry.get()
        if not validate_binary(key):
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return
        key = list(map(int, key))
        if len(key) != 10:
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return

        ciphertext = encrypt_ascii_text(plaintext, key)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
        messagebox.showinfo("Encryption", "成功使用给定密钥加密明文")

    def decrypt_text():
        ciphertext = input_text.get()
        key = key_entry.get()
        if not validate_binary(key):
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return
        key = list(map(int, key))
        if len(key) != 10:
            messagebox.showerror("输入错误", "密钥应为10位二进制数")
            return

        plaintext = decrypt_ascii_text(ciphertext, key)
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext)
        messagebox.showinfo("Decryption", "成功使用给定密钥解密密文")

    def validate_binary(binary_string):
        return all(bit in '01' for bit in binary_string)

    def random_key():
        messagebox.showinfo("随机密钥", generate_random_key())

    # 创建主窗口
    root = tk.Tk()
    root.title("S-DES 加解密GUI（ASCII版）")

    # 设置GUI窗口大小
    root.geometry("600x400")

    # 创建标签和文本框用于输入明文/密文和密钥
    encrypt_button = tk.Button(root, text="随机生成密钥", command=random_key)
    encrypt_button.pack()
    input_label = tk.Label(root, text="输入明文或密文（支持中文）:")
    input_label.pack()
    input_text = tk.Entry(root)
    input_text.pack()

    key_label = tk.Label(root, text="密钥（10位二进制数）:")
    key_label.pack()
    key_entry = tk.Entry(root)
    key_entry.pack()

    # 创建加密和解密按钮
    encrypt_button = tk.Button(root, text="加密", command=encrypt_text)
    encrypt_button.pack()
    encrypt_button.pack()

    decrypt_button = tk.Button(root, text="解密", command=decrypt_text)
    decrypt_button.pack()

    # 创建文本框用于显示明文和密文
    plaintext_label = tk.Label(root, text="明文:")
    plaintext_label.pack()
    plaintext_entry = tk.Entry(root)
    plaintext_entry.pack()

    ciphertext_label = tk.Label(root, text="密文:")
    ciphertext_label.pack()
    ciphertext_entry = tk.Entry(root)
    ciphertext_entry.pack()

    # 启动主事件循环
    root.mainloop()

if __name__ == "__main__":
    #main()
    asc()