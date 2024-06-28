import React, { useState } from "react";
import { Container, Form, Row, Col, Button } from 'react-bootstrap';

export const Register = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [registerSuccess, setRegisterSuccess] = useState('');
    const [registerError, setRegisterError] = useState('');
    const [info, setInfo] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        return fetch(`http://${window.location.hostname}:8000/register`, {
            method: "POST",
            mode: "cors",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password,
                info: info ? info : ''
            })
        }).then(res => res.json()).then(data => {
            if (data.error) {
                setRegisterError(data.error);
                setRegisterSuccess('')
            }
            else {
                setRegisterSuccess('Registration done!')
                setRegisterError('');
            }
        })
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
                <Form.Group as={Row} className="mb-3 mt-3">
                    <Form.Label column sm="2">
                        Bio
                    </Form.Label>
                    <Col sm="10">
                        <Form.Control type="text" placeholder="Tell something about you" onChange={(e) => setInfo(e.target.value)} />
                    </Col>
                </Form.Group>
                <Button type="submit">Register</Button>
                <Row style={{ color: "red" }}>
                    {registerError}
                </Row>
                <Row style={{ color: "green" }}>
                    {registerSuccess}
                </Row>
            </Form>
        </Container>
    )
}