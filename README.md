<h1>Server Sleep Safe</h1><br>
<p>Disclaimer: USE RESPONSABLY!**</p><br>
<h3>A simple Python Script designed to seamlessly run your Server in Wake on Demand mode, without noticable latency.</h3><br>
<p>This script, when running on a laptop, will make your server around 7x more power efficient.  It's not even hard.  Just know the IP address of the server, run the script, and BAM.</p>
<p>This script, when running on a microcontroller, will make your server around 18x more power efficient.</p></br>

<h3>Responsable Usage</h3>
<p>This script should only be used on networks where you are the network administrator.</p>
<p>By copying/downloading/modifying/running this program, you agree that you have read and understand the LICENSE, and that you agree with the LICENSE</p>

<h4>How it Works</h4>
<p>It's not magic!</p>
<p>The script simply tells the router that your device is the server, when the serrver goes offline.</p>
<p>When your device recieves something acceptable, it tells the client that you exist.  Next it wakes the server, and transparently forwards the data to the server.</p>
<p>The server then responds to the request(s) like normal, then goes back to sleep.</p>

<h5>Performace Impacts</h5>
<p>Since the Hard Drive can begin reading contents as soon as it recieves power, the same for Solid State, you only see about 10 milliseconds of aditional latency.</p>
<p>The 10ms increased latency is only for the first packet, and can acceptably be considered regular jitter.</p><br>
<p>This script is not recommended for servers who are recieving over 86400 hits per day!</p>
<p>The reason being, is that, it would take more power for your server to sleep and wake up once every second, than it would doing so every 2 seconds or more.</p>

<h6>How to Install</h6>
<ol>
<li>Have Linux installed on your lower powered machiene</li>
<li>Get Two Machines (Your Server, and your lower powered Machiene)</li>
<li>Connect both to the same Local Area Network (LAN) a.k.a. your router</li>
<li>Download and Install Python 3 on your lower powered Machiene</li>
<li>Download this Script on your lower powered Machiene</li>
<li>Know the Private IP address of your server</li>
<li>Know the interface name of your lower powered Machiene (can enter the command ifconfig and look for largest section)</li>
<li>Know the IP address that corresponded with the command you just executed</li>
<li>Enter the command "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP" on your lower powered machiene, and enter your password when prompted</li>
<li>Modify the 3 variables at the start of the script, (serv_ip, self_ip, netif), to match what you know</li>
<li>START UP THE SERVER!</li>
<li>Set your server to sleep after it has been idle for more than 30 seconds</li>
<li>RUN THE SCRIPT!</li>
<li>YAY, you are now eligable for MASSIVE POWER SAVINGS, congradulate yourself</li>
</ol>
