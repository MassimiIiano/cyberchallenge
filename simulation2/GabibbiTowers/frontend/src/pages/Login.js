import React, { useState, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { UserContext } from '../App';
import { Form, Row, Col, Container, Button } from 'react-bootstrap';

export const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loginFailed, setLoginFailed] = useState(false);
    const { user, setUser } = useContext(UserContext);
    const navigate = useNavigate()

    const handleSubmit = (e) => {
        e.preventDefault();
        return fetch(`http://${window.location.hostname}:8000/login`, {
            method: "POST",
            mode: "cors",
            redirect: "follow",
            credentials: "include",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        }).then((res) => {
            if (res.status === 200) {
                return res.json();
            } else {
                throw new Error("Invalid credentials")
            }
        }).then(data => {
            setUser([data.username, data.info]);
            navigate("/profile");
        })
            .catch(e => setLoginFailed(true));
    }

    return (
        <Container>
            <Form onSubmit={handleSubmit}>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Username
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control placeholder="username" onChange={(e) => setUsername(e.target.value)} />
                    </Col>
                </Form.Group>
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Password
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control type="password" placeholder="password" onChange={(e) => setPassword(e.target.value)} />
                    </Col>
                </Form.Group>
                <Button type="submit">Login</Button>
                {loginFailed ? <Row style={{ color: "red" }}>Login failed</Row> : <Row></Row>}
            </Form>
        </Container>
    )
}