from setuptools import setup, find_packages

setup(
    name='zsigner',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        # Eğer başka paketlere ihtiyaç varsa buraya ekle
        # Örnek: 'requests', 'colorama', 'user_agent'
    ],
    python_requires='>=3.8',
    description='TikTok X-Bogus ve X-Gnarly imza oluşturucu',
    author='ZEUS',
    url='https://github.com/Z4usXcode/ZSigner',
)
