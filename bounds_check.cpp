#include <iostream>

void foo1() {
    std::cout << "You shouldn't be here" << std::endl;
}


int main() {
    int input;
    char buffer[10];

    std::cout << "Enter a number and we will tell you if it is even or odd: ";
    std::cin >> buffer;

}