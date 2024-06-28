import { useLocation } from 'react-router-dom';
import { UserContext } from '../App';
import { useContext } from "react";
import { Row, Col, Container } from "react-bootstrap";

export const Profile = () => {
    const location = useLocation();
    const { user, setUser } = useContext(UserContext);

    return (
        <>
            {!!user ?
                <Container>
                    <Row className='mt-3'>
                        <Col sm="3">
                            Username:
                        </Col>
                        <Col>
                            {user[0]}
                        </Col>
                    </Row>
                    <Row className='mt-3'>
                        <Col sm="3">
                            Bio:
                        </Col>
                        <Col>{user[1]}</Col>
                    </Row>
                </Container> :
                <Row></Row>
            }
        </>
    )
}