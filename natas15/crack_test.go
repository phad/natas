package main

import (
	"fmt"
	"testing"
)

const secret = "JkhsDF67asz+nj/DFNuasAS64rwsdayu"

func oracleEq(try string, pos int) (bool, error) {
	if pos < 0 || pos > len(secret) {
		panic(fmt.Sprintf("pos out of range, want 0 <= pos < 32", pos))
	}
	return try[0:pos+1] == secret[0:pos+1], nil
}

func TestCrackEq(t *testing.T) {
	cracked, err := crackEq(oracleEq, 32)
	if err != nil {
		t.Errorf("Should have been cracked; got %v", err)
	}
	if cracked != secret {
		t.Errorf("Cracked OK but wrong answer. got %v want %v", cracked, secret)
	}
}
