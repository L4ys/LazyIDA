# LazyIDA
Make your IDA Lazy!

# Install
Just put `LazyIDA.py` into plugin folder under your IDA Pro installation path.

#Features
  - Remove function return type in Hex-Rays:
  
![2016-06-12 11 05 29](https://cloud.githubusercontent.com/assets/5360374/15991889/2dad5d62-30f2-11e6-8d4b-e4efb0b73c77.png)

  - Convert data into different formats:
  
![2016-06-12 11 01 57](https://cloud.githubusercontent.com/assets/5360374/15991854/b813070a-30f1-11e6-931e-08ae85355cca.png)
![2016-06-12 11 03 18](https://cloud.githubusercontent.com/assets/5360374/15991863/e5271146-30f1-11e6-89ac-bafd46eb1e45.png)
  - Scan for format string vulnerabilities:
  
![2016-06-12 11 04 31](https://cloud.githubusercontent.com/assets/5360374/15991877/0af77a96-30f2-11e6-98c4-950477595adc.png)
  - Auto fix CGC syscall comment:

![2016-06-12 11 14 25](https://cloud.githubusercontent.com/assets/5360374/15991947/71542072-30f3-11e6-9e6b-d453ee427f87.png)
  - Lazy shortcuts:
    - Disasm Window: 
      - `w`: Copy address of current line into clipboard
    - Hex-rays Window: 
      - `w`: Copy address of current item into clipboard
      - `c`: Copy name of current item into clipboard
      - `v`: Remove return type of current item
