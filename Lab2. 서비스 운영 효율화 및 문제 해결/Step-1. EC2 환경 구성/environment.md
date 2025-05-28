# 서비스 운영 효율화 및 문제 해결

## Amazon Q Developer CLI를 활용

### 01. Amazon Q Developer CLI를 활용한 인스턴스 생성

```bash
t3.micro 2개, t3.medium 2개 생성해줘.
```

![alt text](../others/Lab2-img-1.png)
![alt text](../others/Lab2-img-2.png)


### 02. Amazon Q Developer CLI를 활용한 인스턴스 태깅 작업

```bash
방금 생성한 t3.micro 인스턴스에 t3.micro라고 태깅 붙여줘. 
```

![alt text](../others/Lab2-img-3.png)

```bash
방금 생성한 t3.medium 인스턴스에 t3.medium라고 태깅 붙여줘. 
```

### 03. Amazon Q Developer CLI를 활용한 인스턴스 타입별 예상 금액

```bash
t3.micro, t3.medium 인스턴스 타입에 대해서 이번달 인스턴스 금액을 예상해볼 수 있을까? 
```

![alt text](../others/Lab2-img-4.png)


### 04. Amazon Q Developer CLI를 활용한 Stage별 태깅 추가 작업

```bash
t3.micro에는 test, t3.medium에는 prod라고 태깅을 붙여줘.
```

![alt text](../others/Lab2-img-5.png)


### 05. Amazon Q Developer CLI를 활용한 인스턴스 타입별, Stage별 예상 금액 md 파일로 생성

```bash
t3.micro, t3.medium 인스턴스를 InstanceType, Environment를 고려해서 월별 예상 금액을 뽑고 싶어. 그리고 그 결과를 md 파일 형태로 받고 싶어.
```

![alt text](../others/Lab2-img-6.png)
![alt text](../others/Lab2-img-7.png)

### 06. Amazon Q Developer CLI를 활용한 인스턴스 모니터링 환경 

```bash
t3.micro, t3.medium 인스턴스를 모니터링하는 cloudwatch 대시보드를 구성하고 싶어. CPU, RAM 및 다양한 모니터링 항목을 구성하고 싶어.
```