from setuptools import setup, find_packages

setup(
    name='ZSigner',               # Paket adı PyPI’de görünecek isim
    version='0.1.0',              # İlk sürüm numarası
    packages=find_packages(),      # zsigner klasörünü bulur
    install_requires=[],           # Eğer başka paketlere bağımlıysa buraya ekle
    python_requires='>=3.8',      # Python versiyonunu belirt
    description='TikTok X-Bogus ve X-Gnarly imza oluşturucu',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='ZEUS',
    url='https://github.com/Z4usXcode/ZSigner',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
