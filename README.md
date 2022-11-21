<h1 align="center">
Digital Signature ALgorithm 🔑
</h1>

## Summary
- [Set Up](#set-up-)
- [Generate the keys and assert the properties](#generate-the-keys-and-assert-the-properties-)

## Set up 📦

### Create and enable a virtual environment

```
    $ pip install virtualenv
    $ python -m venv venv
    $ source venv/bin/activate
```

### Install the dependencies

```
    $ pip install -r requirements.txt
```

## Generate the keys and assert the properties 🔑
For generating all the values needed for the DSA algorithm and assert the properties between them, execute the following command:

```
    $ python main.py [-l <lvalue>]
```
The parameter -l is the length of the first prime, and by default (if not specified) is 2048.

If a parameter isn't correct, the program will raise an AssertionError.
