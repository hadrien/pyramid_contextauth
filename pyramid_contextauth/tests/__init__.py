# -*- coding: utf-8 -*-
import os


def setUpPackage():
    os.environ['MONGO_URI'] = 'mongodb://localhost'
    os.environ['MONGO_DB_NAME'] = 'pyramid_mongokit'


def tearDownPackage():
    del os.environ['MONGO_URI']
    del os.environ['MONGO_DB_NAME']
