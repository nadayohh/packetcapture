#3S 패킷 분석 SW 제작 프로젝트

###<인원 구성>
- 이은기 : PM, TELNET 프로토콜 구현
- 전서연 : SMTP 프로토콜 구현
- 지현아 : ARP 프로토콜 구현
- 황선영 : HTTP 프로토콜 구현

###<주요 기능>
1. 네트워크 어댑터 설정
   -연결할 수 있는 어댑터 목록을 출력하고, 사용자가 스니핑할 디바이스를 선택함.
   -PCAP 라이브러리에 내장된 함수들을 사용하여 어댑터 목록을 출력하고, 포인터로 선택한 디바이스 데이터를 저장
   -지목된 디바이스의 데이터를 PCAP_OPEN_LIVE의 인자로 넣어 해당 디바이스의 패킷을 무작위 모드로 볼 수 있게끔 설정
    
2. 패킷 캡쳐
   -설정된 어댑터의 패킷을 출력하고, 사용자가 키보드의 'P'를 누르면 캡쳐를 멈춤
   -PCAP_NEXT_EX 함수를 어댑터의 패킷 데이터를 차례대로 출력함
   -무한 루프문을 통해 구현되며, _KBHIT() 함수를 통해 탈출할 수 있음
   
3. 필터링 기능
  -모든 패킷을 캡쳐하되, 사용자가 지정한 패킷만 출력하도록 함(현재는 프로토콜만을 필터링 할 수 있음)
  -패킷 캡쳐를 통해 얻은 패킷을 구조체를 사용하여 세부 데이터를 구분함

5. 패킷 세부 정보 출력
   -패킷이 수집된 순서, 패킷의 전송 시간, 소스 IP, 목적지 IP, 프로토콜, 길이 정보를 출력한다
   -패킷의 ip 헤더 상에 있는 전송 시간, 소스 IP, 목적지 IP, 프로토콜, 길이 정보를 구조체를 이용해 구별 