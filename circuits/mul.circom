template Mul() {
    // private inputs
    signal input a;
    signal input b;

    // public inputs
    signal input expected;

    expected === a * b;
}

component main {public [
    expected
]} = Mul();
