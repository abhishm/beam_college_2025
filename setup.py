import setuptools

setuptools.setup(
  name='security_dashboard',
  version='0.1',
  install_requires=[
      "google-genai",
      "pyod"
  ],
  packages=setuptools.find_packages(),
)