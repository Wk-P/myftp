import socket
import tkinter as tk
import tkinter.filedialog as fd
from tkinter import messagebox, simpledialog
import os
import queue
from typing import BinaryIO
import json
import re
import subprocess
import threading
from pathlib import Path

def get_parent_path():
    current_file = Path(__file__).resolve()
    return current_file.parent


def get_default_gateway_interface():
    try:
        result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
        if result.returncode == 0:
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                match = re.search(r'^\s*0.0.0.0\s+0.0.0.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+', line)
                if match:
                    gateway_ip = match.group(1)
                    interface_ip = match.group(2)
                    return match.group(1), match.group(2)
    except Exception as e:
        print("Error:", e)
    return None, None

# 自定义类
class ChunkPackage():
    def __init__(self, content:bytes, byte_size=1024):
        self.n_bytes = byte_size
        self.content = content


class File():
    def __init__(self, **kw):
        try:
            if "file" in kw:
                self.file:BinaryIO = kw.get('file')
                self.mode = self.file.mode
            else:
                if "mode" in kw and "filepath" in kw:
                    self.mode = kw.get("mode")
                    self.path = kw.get("filepath")
                    self.file:BinaryIO = open(self.path, self.mode)
                else:
                    raise OSError
            self.suffix_list = ['txt', 'jpg', 'png', 'py']
            self.type_list = ['text', 'pic']
            self.path = self.file.name
            self.name = self.path.replace("\\","/").split('/')[-1].split('.')[0]
            self.suffix = self.path.split('.')[-1]
            self.size = os.path.getsize(self.path)
            self.type = self.__filetype__()
        except:
            self.file.close()

    def read(self, size):
        return self.file.read(size)
    
    def write(self, buffer):
        return self.file.write(buffer)
    
    def close(self):
        return self.file.close()

    def __filetype__(self):
        if self.suffix in self.suffix_list:
            if self.suffix in ('txt', 'py'): 
                return "text"
            elif self.suffix in ('jpg', 'png'):
                return "pic"

    def __str__(self):
        return f"{self.path} | {self.type} | {self.suffix} | {self.mode}"

class FileManager():
    def __init__(self, receive_socket:socket.socket=None, send_socket:socket.socket=None, recv_path=None):
        self.path_list = list()
        self.file_queue = queue.Queue()
        self.package_queue = queue.Queue()
        self.send_socket = send_socket
        self.receive_socket = receive_socket
        self.receive_host, self.receive_port = receive_socket.getsockname()
        self.receive_path = recv_path


    def enter_addr(self):
        input_addr = [None, None]
        # 创建一个新的顶级窗口
        dialog = tk.Toplevel()
        dialog.title("输入主机信息")

        # 输入主机地址的提示和输入框
        host_label = tk.Label(dialog, text="请输入主机地址:")
        host_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        host_entry = tk.Entry(dialog)
        host_entry.grid(row=0, column=1, padx=5, pady=5)

        # 输入端口号的提示和输入框
        port_label = tk.Label(dialog, text="请输入端口号:")
        port_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        port_entry = tk.Entry(dialog)
        port_entry.grid(row=1, column=1, padx=5, pady=5)
       
        def on_ok(args):
            host = host_entry.get()
            port = port_entry.get()
            # 检查主机地址和端口号格式
            if host == "":
                messagebox.showerror("错误", "主机地址格式不正确！")
                dialog.attributes("-topmost", True)
                return 
            if port == "":
                messagebox.showerror("错误", "端口号格式不正确！")
                dialog.attributes("-topmost", True)
                return
            
            args[0] = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host).group()
            args[1] = int(re.match(r'^\d{1,5}$', port).group())

            dialog.destroy()
            return
        
        ok_button = tk.Button(dialog, text="确认", command=lambda: on_ok(input_addr))
        ok_button.grid(row=2, columnspan=2, pady=10)

        # 进入消息循环等待对话框关闭
        dialog.wait_window(dialog)
        return input_addr

    # 管理 send_socket 的目标地址
    def send_connect(self):
        host, port = self.enter_addr()
        if host and port:
            try:
                self.send_socket.connect((host, port))
                messagebox.showinfo("连接成功", "连接成功，请添加发送文件")
            except:
                messagebox.showerror("连接失败", "目标服务器不可连接")
        else:
            messagebox.showwarning("输入错误", "请输入有效的主机地址和端口号")
            


    def check_send_connect(self):
        try:
            # 尝试获取远程主机的地址信息
            remote_addr = self.send_socket.getpeername()
            if remote_addr:
                # 如果获取成功且不为空，表示连接成功
                return True
            else:
                # 如果获取成功但为空，表示连接未建立
                return False
        except:
            # 如果发生异常，表示连接未建立
            return False


    # 分割文件装成包
    def split_binary_file(self, file:File, chunk_size=1024):
        chunk_number = 0
        # 首先生成HEAD
        tag = {
            "Content-Type": "json",
            "Filename": file.name, 
            "SourcePath": file.path,
            "Suffix": file.suffix,
            "Size": file.size,
            "FileType": file.type
        }
        # 发送头信息
        self.package_queue.put(ChunkPackage(content=f"{json.dumps(tag)}".encode(), byte_size=chunk_size))

        # 发送文件本体
        while True:
            chunk = file.read(chunk_size)
            if file.size == 0:
                chunk_number += 1
                break
            if not chunk:
                break
            self.package_queue.put(ChunkPackage(content=chunk, byte_size=chunk_size))
            chunk_number += 1
        self.package_queue.put(ChunkPackage(content=b'EOF', byte_size=8))
        return chunk_number + 1


    # test function
    def test_send_first_file(self):
        filepath = fd.askopenfilename()
        if filepath:
            self.send_connect()
            self.send_file(File(filepath=filepath, mode='rb'))
        else:
            print("请选择文件")


    # test funciton
    def send_one_file(self):
        filepath = fd.askopenfilename()
        if filepath:
            self.send_connect()
            return self.send_file(File(filepath=filepath, mode='rb'))
        else:
            print("请重新选择文件")
            return False


    def send(self):
        self.send_socket.sendall()


    def send_file(self, file:File):
        try:
            packages_number = self.split_binary_file(file)
            for _ in range(packages_number):
                while not self.package_queue.empty():
                    self.send_socket.sendall(self.package_queue.get().content)
            return True
        except:
            return False


    # 发送所有文件
    def send_all_files(self):
        try:
            if self.file_queue.empty():
                messagebox.showerror("Error", "没有可发送文件")
                return False
            # 依次取出队列中的文件
            while not self.file_queue.empty():
                file:File = self.file_queue.get()
                self.send_file(file)
            return True
        except:
            return False

    def parse_string(self, bytes_string):
        try:
            # 尝试解析为 JSON
            obj = json.loads(bytes_string)
            return obj
        except ValueError:
            # 解析失败，返回原始字符串
            return bytes_string


    def receive_file(self):
            while True:
                try:
                    sock, _ = self.receive_socket.accept()
                    recv_file = None  # 确保先定义
                    while True:
                        data = sock.recv(1024)
                        if not data:
                            break
                        data = self.parse_string(data)
                        if isinstance(data, dict):
                            # 文件信息
                            name = data['Filename']
                            suffix = data['Suffix']
                            recv_file:File = File(filepath=f"{self.receive_path}/{name}.{suffix}", mode='wb')
                        else:
                            if data[-3:] == b'EOF':
                                data = data[:-3]
                                break
                            recv_file.write(data)
                    
                    if data != b"":
                        recv_file.write(data)
                    
                    if "recv_file" in locals():
                        messagebox.showinfo("Info", f"文件{recv_file.name}接收完毕")
                        recv_file.close()
                        return True
                except OSError as e:
                    if not isinstance(e, socket.error):
                        messagebox.showerror("Error", f"文件{recv_file.name}接收失败\nError:{e}")
                        if "recv_file" in locals():
                            recv_file.close()
                    else:
                        self.receive_socket.close()
                        break

# 应用界面处理
def add_path(manager:FileManager, listbox:tk.Listbox):
    def open_file_dialog():
        filepath = fd.askopenfilename()
        filename =  os.path.basename(filepath)
        if filename:
            manager.path_list.append(filepath)
            manager.file_queue.put(File(filepath=filepath, mode='rb'))
            listbox.insert(tk.END, filename)
    open_file_dialog()


def clear_listbox(listbox:tk.Listbox):
    if listbox.size():
        # 清空 ListBox 中的所有内容
        listbox.delete(0, tk.END)
    else:
        messagebox.showinfo("提示", "列表已空")


def init(manager:FileManager):
    window=tk.Tk()
    window.title("Send Files")
    window.geometry("1000x800")

    # 地址信息框架
    addrFrame = tk.Frame(window,  width=400)
    addrFrame.pack(fill=tk.X, padx=200, pady=10)
    
    entry_width = 40

    addrTextLabel = tk.Label(addrFrame, text="主机地址:")
    addrTextLabel.pack(side=tk.LEFT, )

    # 地址输入框
    addrEntry = tk.Entry(addrFrame, width=entry_width)
    addrEntry.insert(0, manager.receive_socket.getsockname()[0])
    addrEntry.pack(side=tk.LEFT, padx=(0, 5), ipadx=5)

    portTextLabel = tk.Label(addrFrame, text="接收端口:")
    portTextLabel.pack(side=tk.LEFT, )

    # 端口输入框
    portEntry = tk.Entry(addrFrame, width=entry_width)
    portEntry.insert(0, manager.receive_socket.getsockname()[1])
    portEntry.pack(side=tk.LEFT, padx=(0, 5), ipadx=5)


    # 文件发送区
    labelFrame = tk.Frame(window, bd=1,  relief="solid")
    sendLabelFrameTitle = tk.Label(labelFrame, text="发送列表")
    sendLabelFrameTitle.pack()
    labelListBox = tk.Listbox(labelFrame, justify='center', width=150)
    labelListBox.pack_propagate(False)

    # scrollbar 组件
    yscrollbar = tk.Scrollbar(labelFrame, orient="vertical", command=labelListBox.yview)

    buttonFrame = tk.Frame(window, bd=1, relief="ridge", height=50, width=300)


    labelListBox.config(yscrollcommand=yscrollbar.set)
    yscrollbar.pack(side="right", fill="y")

    labelListBox.pack(side="left", fill="both", expand=True)
    labelFrame.pack()


    recvLabelFrame = tk.Frame(window, bd=1,  relief="solid")
    recvlabelListBox = tk.Listbox(recvLabelFrame, justify='center', width=150)
    recvlabelListBox.pack_propagate(False)

    # scrollbar 组件
    recvyscrollbar = tk.Scrollbar(recvLabelFrame, orient="vertical", command=labelListBox.yview)


    recvlabelListBox.config(yscrollcommand=recvyscrollbar.set)
    recvyscrollbar.pack(side="right", fill="y")

    recvlabelListBox.pack(side="left", fill="both", expand=True)
    recvLabelFrame.pack()
    
    buttonFrame.pack()

    def send_all_files(listBox):
        if manager.check_send_connect():
            if manager.send_all_files():
                messagebox.showinfo("成功", "文件发送完成")
                clear_listbox(listBox)
            else:
                messagebox.showerror("错误", "文件发送失败")
        else:
            manager.send_connect()

    add_file_button = tk.Button(buttonFrame, text="添加文件", height=2, anchor="center", justify="center", command=lambda: add_path(manager=manager, listbox=labelListBox))
    add_file_button.pack()

    send_button = tk.Button(buttonFrame, text="发送文件", height=2, anchor="center", justify="center", command=lambda: send_all_files(labelListBox))
    send_button.pack()

    clear_button = tk.Button(buttonFrame, text="清空文件", height=2, anchor="center", justify="center", command=lambda: clear_listbox(labelListBox))
    clear_button.pack()

    

    def end(window:tk.Tk):
        window.destroy()
        manager.receive_socket.close()

    recv_thread = threading.Thread(target=manager.receive_file)
    recv_thread.start()

    window.protocol("WM_DELETE_WINDOW", lambda: end(window=window))

    window.mainloop()

if __name__ == "__main__":
    # file_path = "./Internet/pic/服务端.py"
    gateway, host = get_default_gateway_interface()
    receive_port = 8332
    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receive_socket.bind((host, receive_port))
    receive_socket.listen(5)
    
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receive_path = get_parent_path() / r"receive"
    fm = FileManager(send_socket=send_socket, receive_socket=receive_socket, recv_path=receive_path)
    init(manager=fm)
    
    send_socket.close()
    receive_socket.close()
