from bs4 import BeautifulSoup
import os

def html_to_markdown(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 提取标题
    title = soup.select_one("h1.title-article").get_text()
    
    # 提取文章正文内容
    article_content = soup.select_one("#content_views")
    
    # 初始化 Markdown 字符串
    markdown_content = f"# {title}\n\n"
    
    # 辅助函数：转换带样式文本为 Markdown
    def convert_text(element):
        text = ''
        for segment in element.contents:
            if isinstance(segment, str):
                text += segment
            elif segment.name == 'em':  # 斜体
                text += f"*{segment.get_text()}*"
            elif segment.name == 'strong':  # 加粗
                text += f"**{segment.get_text()}**"
            elif segment.name == 'mark':  # 标记
                text += f"=={segment.get_text()}=="
            elif segment.name == 'del':  # 删除线
                text += f"~~{segment.get_text()}~~"
            elif 'katex' in segment.get('class', []):  # KaTeX 公式  //不完善
                text += f"${segment.get_text()}$"  # 使用行内公式格式
            else:
                text += segment.get_text()
        return text

    # 遍历文章内容
    for element in article_content.find_all(['h1', 'h2', 'h3', 'p', 'img', 'pre', 'span']):
        if element.name == 'h1':
            markdown_content += f"# {element.get_text()}\n\n"
        elif element.name == 'h2':
            markdown_content += f"## {element.get_text()}\n\n"
        elif element.name == 'h3':
            markdown_content += f"### {element.get_text()}\n\n"
        elif element.name == 'p':
            markdown_content += f"{convert_text(element)}\n\n"
        elif element.name == 'img':
            markdown_content += f"![{element.get('alt', '')}]({element.get('src')})\n\n"
        elif element.name == 'pre':
            code = element.find('code')
            if code:
                language = code.get('class', [''])[0].replace('language-', '')
                markdown_content += f"```{language}\n{code.get_text()}\n```\n\n"
        elif 'katex' in element.get('class', []):  # 处理 KaTeX 公式
            markdown_content += f"${element.get_text()}$\n\n"

    return markdown_content.strip(), title.strip()

def save_markdown_to_file(markdown_content, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(markdown_content)

# 读取 input.txt 文件内容
with open('input.txt', 'r', encoding='utf-8') as file:
    html_content = file.read()

markdown_result, title = html_to_markdown(html_content)
# 将文件名替换为文章的一级标题，并加上 .md 后缀
safe_title = title.replace('/', '_')  # 替换文件名中的非法字符
save_markdown_to_file(markdown_result, f'{safe_title}.md')

print(f"Markdown 文件已保存为 {safe_title}.md")
