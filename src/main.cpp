#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gnutls/gnutls.h>
#include <gnutls/gnutlsxx.h>

namespace {

const std::string ca_certificates_file_path = "/etc/ssl/certs/ca-certificates.crt";

const int port = 443;
const std::string server = "google.com";

const size_t MAX_BUF = 4 * 1024; // 4k read buffer

std::string hostname_to_ip(const std::string& hostname)
{
    const struct hostent* he = gethostbyname(hostname.c_str());

    if (he == nullptr) {
        std::cerr<<"hostname_to_ip gethostbyname failed, errno="<<errno<<std::endl;
        return "";
    }

    const struct in_addr** addr_list = (const struct in_addr**)he->h_addr_list;

    for (int i = 0; addr_list[i] != nullptr; i++) {
        // Get the first result
        const std::string ip = inet_ntoa(*addr_list[i]);
        return ip;
    }
    
    return "";
}

// Connects to the peer and returns a socket descriptor
int tcp_connect(const std::string& ip, int port)
{
    // Connect to server
    const int sd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sa;
    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    const int result = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
    if (result < 0) {
        fprintf(stderr, "Connect error\n");
        exit(1);
    }

    return sd;
}

// Closes the given socket descriptor
void tcp_close(int sd)
{
    shutdown(sd, SHUT_RDWR); // No more receptions or transmissions
    close(sd);
}


enum class POLL_READ_RESULT {
    ERROR,
    DATA_READY,
    TIMED_OUT
};

class poll_read {
public:
    explicit poll_read(int fd);

    POLL_READ_RESULT poll(int timeout_ms);

private:
    struct pollfd fds;
};

poll_read::poll_read(int fd)
{
    // Monitor the fd for input
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;
}

POLL_READ_RESULT poll_read::poll(int timeout_ms)
{
    fds.revents = 0;

    const int result = ::poll(&fds, 1, timeout_ms);
    if (result < 0) {
        return POLL_READ_RESULT::ERROR;
    } else if (result > 0) {
        if ((fds.revents & POLLIN) != 0) {
            // Zero it out so we can reuse it for the next call to poll
            fds.revents = 0;
            return POLL_READ_RESULT::DATA_READY;
        }
    }

    return POLL_READ_RESULT::TIMED_OUT;
}


size_t get_bytes_available(int fd)
{
    int bytes_available = 0;
    ::ioctl(fd, FIONREAD, &bytes_available);
    return size_t(std::max(0, bytes_available));
}

bool sleep_ms(int timeout_ms)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return false;
    }

    const uint64_t absolute_timeout_ns = ((ts.tv_sec * 1000000000L) + ts.tv_nsec) + (timeout_ms * 1000000);
    ts.tv_sec = absolute_timeout_ns / 1000000000L;
    ts.tv_nsec = absolute_timeout_ns % 1000000000L;

    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, nullptr) && errno == EINTR)
        ;

    return true;
}

}


int main(void)
{
    int sd = -1;
    gnutls_global_init();

    try {
        // Allow connections to servers that have OpenPGP keys as well
        gnutls::client_session session;

        // X509 stuff
        gnutls::certificate_credentials credentials;

        // Set the trusted cas file
        credentials.set_x509_trust_file(ca_certificates_file_path.c_str(), GNUTLS_X509_FMT_PEM);

        // Put the x509 credentials to the current session
        session.set_credentials(credentials);

        // Set TLS version and cypher priorities
        // https://gnutls.org/manual/html_node/Priority-Strings.html
        // NOTE: No SSL, only TLS1.2
        // TODO: TLS1.3 didn't seem to work, server dependent?
        //session.set_priority ("NORMAL:+SRP:+SRP-RSA:+SRP-DSS:-DHE-RSA:-VERS-SSL3.0:%SAFE_RENEGOTIATION:%LATEST_RECORD_VERSION", nullptr);
        session.set_priority("SECURE128:+SECURE192:-VERS-ALL:+VERS-TLS1.2:%SAFE_RENEGOTIATION", nullptr);

        // connect to the peer
        const std::string ip = hostname_to_ip(server);
        sd = tcp_connect(ip, port);
        session.set_transport_ptr((gnutls_transport_ptr_t)(ptrdiff_t)sd);

        // Perform the TLS handshake
        const int result = session.handshake();
        if (result < 0) {
            throw std::runtime_error("Handshake failed, error " + std::to_string(result));
        }

        std::cout << "Handshake completed" << std::endl;

        std::cout << "Sending HTTP request" << std::endl;
        const std::string request = "GET / HTTP/1.0\r\n\r\n";
        session.send(request.c_str(), request.length());

        std::cout << "Reading response" << std::endl;
        std::ofstream ofs("output.html", std::ofstream::trunc);

        char buffer[MAX_BUF + 1];

        poll_read p(sd);

        const int timeout_ms = 2000;

        // Once we start not receiving data we retry 10 times in 100ms and then exit
        size_t no_bytes_retries = 0;
        const size_t max_no_bytes_retries = 10;
        const size_t retries_timeout_ms = 10;

        std::string received_so_far;

        bool reading_headers = true;

        // NOTE: gnutls_record_recv may return GNUTLS_E_PREMATURE_TERMINATION
        // https://lists.gnupg.org/pipermail/gnutls-help/2014-May/003455.html
        // This means the peer has terminated the TLS session using a TCP RST (i.e., called close()).
        // Since gnutls cannot distinguish that termination from an attacker terminating the session it warns you with this error code.

        while (no_bytes_retries < max_no_bytes_retries) {
            // Check if there is already something in the gnutls buffers
            if (session.check_pending() == 0) {
                // There was no gnutls data ready, check the socket
                switch (p.poll(timeout_ms)) {
                    case POLL_READ_RESULT::DATA_READY: {
                        // Check if bytes are actually available (Otherwise if we try to read again the gnutls session object goes into a bad state and gnutlsxx throws an exception)
                        if (get_bytes_available(sd) == 0) {
                            //std::cout<<"but no bytes available"<<std::endl;
                            no_bytes_retries++;
                            // Don't hog the CPU
                            sleep_ms(retries_timeout_ms);
                            continue;
                        }
                    }
                    case POLL_READ_RESULT::ERROR: {
                        break;
                    }
                    case POLL_READ_RESULT::TIMED_OUT: {
                        // We hit the 2 second timeout, we are probably done
                        break;
                    }
                }
            }

            const ssize_t result = session.recv(buffer, MAX_BUF);
            if (result == 0) {
                std::cout<<"Peer has closed the TLS connection"<<std::endl;
                break;
            } else if (result < 0) {
                std::cout<<"Read error: "<<gnutls_strerror_name(result)<<" "<<gnutls_strerror(result)<<std::endl;
                break;
            }

            const size_t bytes_read = result;
            //std::cout << "Received " << bytes_read << " bytes" << std::endl;
            if (reading_headers) {
                received_so_far.append(buffer, bytes_read);

                size_t i = received_so_far.find("\r\n\r\n");
                if (i != std::string::npos) {
                    std::cout<<"Headers received"<<std::endl;

                    // Anything after this was file content
                    i += strlen("\r\n\r\n");

                    // We are now up to the content
                    reading_headers = false;

                    std::cout<<"Reading content"<<std::endl;

                    // Add to the file content
                    ofs.write(&received_so_far[i], received_so_far.length() - i);
                }
            } else {
                // Everything else is content
                ofs.write(buffer, bytes_read);
            }
        }

        session.bye(GNUTLS_SHUT_RDWR);

        std::cout<<"Finished"<<std::endl;
    } catch (gnutls::exception &ex) {
        std::cerr << "Exception caught: " << ex.what() << std::endl;
    }


    if (sd != -1) {
        tcp_close(sd);
    }

    gnutls_global_deinit();

    return 0;
}
