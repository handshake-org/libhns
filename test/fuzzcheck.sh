#!/bin/sh
# Check that all of the base fuzzing corpus parse without errors
./hnsfuzz fuzzinput/*
./hnsfuzzname fuzznames/*
