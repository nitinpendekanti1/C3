#include <iostream>

void obfuscatedFunction6(int &input, int &input2) {
    int x = input + input2;
    std::cout << x << std::endl;
}

void obfuscatedFunction4(int &input)
{
    input++;
    int a = 7;
    obfuscatedFunction6(input, a);
}

void obfuscatedFunction3(int &input)
{
    obfuscatedFunction4(input);
    int a = 7;
    obfuscatedFunction6(input, a);
}

void obfuscatedFunction2(int &input)
{
    obfuscatedFunction4(input);
}

void obfuscatedFunction5(int &input)
{
    obfuscatedFunction4(input);
}



void obfuscatedFunction(int &input)
{
    obfuscatedFunction3(input);
    obfuscatedFunction2(input);
    obfuscatedFunction5(input);
}


int main()
{
    // Example: Call the obfuscated function with an input
    int x = 5;
    obfuscatedFunction(x);
    std::cout << x << std::endl;

    return 0;
}