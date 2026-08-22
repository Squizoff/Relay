#include "sdk/relay_client.h"
#include <QApplication>
#include <QCloseEvent>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMainWindow>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStatusBar>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QResizeEvent>
#include <QSizePolicy>
#include <cctype>
#include <cstring>
#include <utility>
#include <vector>

static QString fromUtf8Safe( const char* s )
{
	return s ? QString::fromUtf8( s ) : QString();
}

static QString rtrimSpaces( QString s )
{
	while ( !s.isEmpty() && ( s.endsWith( QChar( ' ' ) ) || s.endsWith( QChar( '\t' ) ) ) )
		s.chop( 1 );
	return s;
}

struct ChatEntry
{
	QString handle;
	QString display;
	QString id;
	bool	e2e = false;
	int		unread = 0;
	bool	active = false;
};

static QString shortPeerId( const QString& peerId )
{
	if ( peerId.isEmpty() || peerId.size() != RELAY_PUBKEY_HEX_LEN )
		return QString();
	return QString( "%1...%2" ).arg( peerId.left( 8 ), peerId.right( 8 ) );
}

class MainWindow final : public QMainWindow {
public:
	explicit MainWindow( RelayClient* client, QString selfHandle, QString selfNick, QString selfId, QWidget* parent = nullptr )
		: QMainWindow( parent )
		, client_( client )
		, selfHandle_( std::move( selfHandle ) )
		, selfId_( std::move( selfId ) )
	{
		(void) selfNick;
		setWindowTitle( "Relay" );
		resize( 1180, 760 );
		setMinimumSize( 980, 640 );
		setObjectName( "mainWindow" );
		buildUi();
		applyStyles();
		appSubtitle_->setText( QString( "@%1 · %2" ).arg( selfHandle_, shortPeerId( selfId_ ) ) );
		statusBar()->showMessage( "Connected" );

		connect( chatSearch_, &QLineEdit::textChanged, this, [this] { refreshFromClient( false ); } );
		connect( chatList_, &QListWidget::currentItemChanged, this, [this]( QListWidgetItem* current, QListWidgetItem* ) {
			if ( !current || !client_ )
				return;
			const QByteArray idUtf8 = current->data( Qt::UserRole ).toString().toUtf8();
			relay_client_open_chat( client_, idUtf8.constData() );
			refreshFromClient( true );
		} );
		connect( chatList_, &QListWidget::itemDoubleClicked, this, [this]( QListWidgetItem* item ) {
			if ( !item || !client_ )
				return;
			const QByteArray idUtf8 = item->data( Qt::UserRole ).toString().toUtf8();
			relay_client_open_chat( client_, idUtf8.constData() );
			refreshFromClient( true );
			input_->setFocus();
		} );
		connect( input_, &QLineEdit::returnPressed, this, &MainWindow::sendMessage );
		connect( sendBtn_, &QPushButton::clicked, this, &MainWindow::sendMessage );
		connect( newChatBtn_, &QPushButton::clicked, this, &MainWindow::addContact );
		connect( refreshBtn_, &QPushButton::clicked, this, [this] { refreshFromClient( false ); } );

		timer_ = new QTimer( this );
		timer_->setInterval( 120 );
		connect( timer_, &QTimer::timeout, this, [this] { refreshFromClient( false ); } );
		timer_->start();

		refreshFromClient( true );
	}

	~MainWindow() override
	{
		shutdownClient();
	}

protected:
	void closeEvent( QCloseEvent* e ) override
	{
		shutdownClient();
		QMainWindow::closeEvent( e );
	}

	void resizeEvent( QResizeEvent* e ) override
	{
		QMainWindow::resizeEvent( e );
		updateBubbleWidths();
	}

private:
	void buildUi()
	{
		auto* central = new QWidget( this );
		central->setObjectName( "central" );
		setCentralWidget( central );

		auto* root = new QVBoxLayout( central );
		root->setContentsMargins( 16, 16, 16, 16 );
		root->setSpacing( 14 );

		auto* topBar = new QWidget( central );
		topBar->setObjectName( "topBar" );
		auto* topBarLayout = new QHBoxLayout( topBar );
		topBarLayout->setContentsMargins( 16, 14, 16, 14 );
		topBarLayout->setSpacing( 12 );

		auto* titleBox = new QWidget( topBar );
		auto* titleLayout = new QVBoxLayout( titleBox );
		titleLayout->setContentsMargins( 0, 0, 0, 0 );
		titleLayout->setSpacing( 2 );
		auto* appTitle = new QLabel( "Relay", titleBox );
		appTitle->setObjectName( "appTitle" );
		appSubtitle_ = new QLabel( "Modern chat interface", titleBox );
		appSubtitle_->setObjectName( "appSubtitle" );
		titleLayout->addWidget( appTitle );
		titleLayout->addWidget( appSubtitle_ );

		newChatBtn_ = new QPushButton( "New chat", topBar );
		newChatBtn_->setObjectName( "primaryButton" );
		refreshBtn_ = new QPushButton( "Refresh", topBar );
		refreshBtn_->setObjectName( "secondaryButton" );

		topBarLayout->addWidget( titleBox );
		topBarLayout->addStretch( 1 );
		topBarLayout->addWidget( refreshBtn_ );
		topBarLayout->addWidget( newChatBtn_ );
		root->addWidget( topBar );

		auto* splitter = new QSplitter( Qt::Horizontal, central );
		splitter->setObjectName( "mainSplitter" );
		splitter->setChildrenCollapsible( false );
		root->addWidget( splitter, 1 );

		auto* left = new QWidget( splitter );
		left->setObjectName( "sidebar" );
		auto* leftLayout = new QVBoxLayout( left );
		leftLayout->setContentsMargins( 14, 14, 14, 14 );
		leftLayout->setSpacing( 12 );

		auto* leftHeader = new QWidget( left );
		auto* leftHeaderLayout = new QVBoxLayout( leftHeader );
		leftHeaderLayout->setContentsMargins( 0, 0, 0, 0 );
		auto* sidebarTitle = new QLabel( "Chats", leftHeader );
		sidebarTitle->setObjectName( "sectionTitle" );
		chatSearch_ = new QLineEdit( leftHeader );
		chatSearch_->setPlaceholderText( "Search chats" );
		chatSearch_->setClearButtonEnabled( true );
		chatSearch_->setObjectName( "searchBox" );
		leftHeaderLayout->addWidget( sidebarTitle );
		leftHeaderLayout->addWidget( chatSearch_ );
		leftLayout->addWidget( leftHeader );

		chatList_ = new QListWidget( left );
		chatList_->setObjectName( "chatList" );
		chatList_->setSelectionMode( QAbstractItemView::SingleSelection );
		chatList_->setHorizontalScrollBarPolicy( Qt::ScrollBarAlwaysOff );
		chatList_->setVerticalScrollMode( QAbstractItemView::ScrollPerPixel );
		chatList_->setFrameShape( QFrame::NoFrame );
		leftLayout->addWidget( chatList_, 1 );

		auto* right = new QWidget( splitter );
		right->setObjectName( "chatPanel" );
		auto* rightLayout = new QVBoxLayout( right );
		rightLayout->setContentsMargins( 0, 0, 0, 0 );
		rightLayout->setSpacing( 12 );

		auto* chatHeader = new QWidget( right );
		chatHeader->setObjectName( "chatHeader" );
		auto* chatHeaderLayout = new QHBoxLayout( chatHeader );
		chatHeaderLayout->setContentsMargins( 16, 14, 16, 14 );
		chatHeaderLayout->setSpacing( 12 );

		auto* avatar = new QLabel( "", chatHeader );
		avatar->setObjectName( "avatar" );
		avatar->setFixedSize( 40, 40 );

		auto* headerTextBox = new QWidget( chatHeader );
		auto* headerTextLayout = new QVBoxLayout( headerTextBox );
		headerTextLayout->setContentsMargins( 0, 0, 0, 0 );
		headerTextLayout->setSpacing( 2 );
		titleLabel_ = new QLabel( "No chat selected", headerTextBox );
		titleLabel_->setObjectName( "chatTitle" );
		chatStatusLabel_ = new QLabel( "Pick a conversation to start", headerTextBox );
		chatStatusLabel_->setObjectName( "chatStatus" );
		headerTextLayout->addWidget( titleLabel_ );
		headerTextLayout->addWidget( chatStatusLabel_ );

		chatMetaLabel_ = new QLabel( QString(), chatHeader );
		chatMetaLabel_->setObjectName( "chatMeta" );
		chatMetaLabel_->setAlignment( Qt::AlignRight | Qt::AlignVCenter );

		chatHeaderLayout->addWidget( avatar );
		chatHeaderLayout->addWidget( headerTextBox );
		chatHeaderLayout->addStretch( 1 );
		chatHeaderLayout->addWidget( chatMetaLabel_ );
		rightLayout->addWidget( chatHeader );

		messagesScroll_ = new QScrollArea( right );
		messagesScroll_->setObjectName( "messagesScroll" );
		messagesScroll_->setWidgetResizable( true );
		messagesScroll_->setFrameShape( QFrame::NoFrame );
		messagesScroll_->setHorizontalScrollBarPolicy( Qt::ScrollBarAlwaysOff );
		messagesScroll_->setVerticalScrollBarPolicy( Qt::ScrollBarAsNeeded );

		messagesHost_ = new QWidget( messagesScroll_ );
		messagesHost_->setObjectName( "messagesHost" );
		messagesHost_->setSizePolicy( QSizePolicy::Expanding, QSizePolicy::Minimum );
		messagesLayout_ = new QVBoxLayout( messagesHost_ );
		messagesLayout_->setContentsMargins( 16, 16, 16, 16 );
		messagesLayout_->setSpacing( 10 );
		messagesLayout_->addStretch( 1 );
		messagesLayout_->setAlignment( Qt::AlignTop );
		messagesScroll_->setWidget( messagesHost_ );
		rightLayout->addWidget( messagesScroll_, 1 );

		auto* composer = new QWidget( right );
		composer->setObjectName( "composer" );
		auto* composerLayout = new QHBoxLayout( composer );
		composerLayout->setContentsMargins( 14, 12, 14, 12 );
		composerLayout->setSpacing( 10 );

		composeLabel_ = new QLabel( "To: (none)", composer );
		composeLabel_->setObjectName( "composeLabel" );
		input_ = new QLineEdit( composer );
		input_->setObjectName( "messageInput" );
		input_->setMaxLength( MAX_TEXT );
		input_->setPlaceholderText( "Type a message and press Enter" );
		sendBtn_ = new QPushButton( "Send", composer );
		sendBtn_->setObjectName( "sendButton" );
		sendBtn_->setCursor( Qt::PointingHandCursor );

		composerLayout->addWidget( composeLabel_ );
		composerLayout->addWidget( input_, 1 );
		composerLayout->addWidget( sendBtn_ );
		rightLayout->addWidget( composer );

		left->setMinimumWidth( 300 );
		right->setMinimumWidth( 520 );
		splitter->addWidget( left );
		splitter->addWidget( right );
		splitter->setStretchFactor( 0, 0 );
		splitter->setStretchFactor( 1, 1 );
		splitter->setSizes( { 360, 800 } );
	}

	void applyStyles()
	{
		setStyleSheet( R"(
#mainWindow, #central {
    background: #0f1419;
    color: #e9edef;
}

#topBar, #sidebar, #chatPanel, #chatHeader, #composer {
    background: #111b21;
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 16px;
}

#avatar {
    background: #25d366;
    border-radius: 20px;
}

#appTitle, #sectionTitle, #chatTitle {
    font-weight: 700;
}

#appTitle {
    font-size: 20px;
}

#sectionTitle {
    font-size: 16px;
}

#appSubtitle, #chatStatus, #chatMeta, #composeLabel {
    color: #8696a0;
    font-size: 12px;
}

#searchBox, #messageInput {
    background: #202c33;
    color: #e9edef;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 12px;
    padding: 10px 14px;
    selection-background-color: #25d366;
}

#searchBox:focus, #messageInput:focus {
    border: 1px solid #25d366;
}

#primaryButton, #secondaryButton, #sendButton {
    border: none;
    border-radius: 12px;
    padding: 10px 14px;
    font-weight: 600;
}

#primaryButton, #sendButton {
    background: #25d366;
    color: #08130d;
}

#secondaryButton {
    background: #202c33;
    color: #e9edef;
}

#chatList {
    background: transparent;
    border: none;
    outline: none;
}

#chatList::item {
    background: #111b21;
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 14px;
    padding: 10px 12px;
    min-height: 48px;
    color: #e9edef;
}

#chatList::item:hover {
    background: #182229;
}

#chatList::item:selected {
    background: #1f2c33;
    border: 1px solid #25d366;
}

#messagesScroll {
    background: #0f1419;
    border: 1px solid rgba(255,255,255,0.04);
    border-radius: 16px;
}

#messagesHost {
    background: transparent;
}

#theirBubble, #mineBubble {
    border-radius: 16px;
    border: 1px solid rgba(255,255,255,0.05);
}

#theirBubble {
    background: #202c33;
}

#mineBubble {
    background: #25d366;
    border-color: rgba(37,211,102,0.25);
}

#bubbleText {
    font-size: 15px;
}
#theirBubble QLabel {
    color: #e9edef;
}
#mineBubble QLabel {
    color: #08130d;
}
)" );
	}

	void shutdownClient()
	{
		if ( !client_ )
			return;
		relay_client_stop( client_ );
		relay_client_destroy( client_ );
		client_ = nullptr;
	}

	QString currentSelectedHandle() const
	{
		if ( auto* item = chatList_->currentItem() )
			return item->data( Qt::UserRole ).toString();
		return QString();
	}

	void setComposerEnabled( bool enabled )
	{
		input_->setEnabled( enabled );
		sendBtn_->setEnabled( enabled );
		newChatBtn_->setEnabled( enabled );
		refreshBtn_->setEnabled( enabled );
		chatSearch_->setEnabled( enabled );
		chatList_->setEnabled( enabled );
	}

	void clearMessages()
	{
		while ( QLayoutItem* item = messagesLayout_->takeAt( 0 ) ) {
			if ( QWidget* w = item->widget() )
				w->deleteLater();
			delete item;
		}
	}

	void resetMessageView()
	{
		clearMessages();
		messagesLayout_->addStretch( 1 );
		renderedChatId_.clear();
		renderedMessageAuthors_.clear();
		renderedMessageTexts_.clear();
	}

	bool isMyMessage( const QString& author ) const
	{
		return author == "me";
	}

	void addMessageBubble( const QString&, const QString& text, bool mine )
	{
		auto* row = new QWidget( messagesHost_ );
		row->setSizePolicy( QSizePolicy::Expanding, QSizePolicy::Minimum );

		auto* rowLayout = new QHBoxLayout( row );
		rowLayout->setContentsMargins( 0, 0, 0, 0 );
		rowLayout->setSpacing( 0 );

		if ( mine )
			rowLayout->addStretch( 1 );

		auto* bubble = new QFrame( row );
		bubble->setObjectName( mine ? "mineBubble" : "theirBubble" );
		bubble->setFrameShape( QFrame::NoFrame );
		bubble->setAttribute( Qt::WA_StyledBackground, true );
		bubble->setSizePolicy( QSizePolicy::Maximum, QSizePolicy::Minimum );

		auto* bubbleLayout = new QVBoxLayout( bubble );
		bubbleLayout->setContentsMargins( 16, 12, 16, 12 );
		bubbleLayout->setSpacing( 0 );

		auto* body = new QLabel( bubble );
		body->setObjectName( "bubbleText" );
		body->setTextFormat( Qt::PlainText );
		body->setWordWrap( true );
		body->setTextInteractionFlags( Qt::TextSelectableByMouse );
		body->setText( text );

		bubbleLayout->addWidget( body );
		rowLayout->addWidget( bubble, 0, mine ? Qt::AlignRight : Qt::AlignLeft );

		if ( !mine )
			rowLayout->addStretch( 1 );

		const int insertPos = qMax( 0, messagesLayout_->count() - 1 );
		messagesLayout_->insertWidget( insertPos, row );
	}

	void updateBubbleWidths()
	{
		if ( !messagesScroll_ || !messagesHost_ )
			return;

		const int viewportWidth = messagesScroll_->viewport()->width();
		const int maxBubbleWidth = qMax( 260, int( viewportWidth * 0.72 ) );

		const auto bubbles = messagesHost_->findChildren<QFrame*>();
		for ( auto* bubble : bubbles ) {
			const QString name = bubble->objectName();
			if ( name == "mineBubble" || name == "theirBubble" )
				bubble->setMaximumWidth( maxBubbleWidth );
		}
	}

	void removeFirstMessageBubble()
	{
		if ( messagesLayout_->count() <= 1 )
			return;

		QLayoutItem* item = messagesLayout_->takeAt( 0 );
		if ( QWidget* w = item->widget() )
			w->deleteLater();
		delete item;
	}

	void refreshFromClient( bool forceScrollToEnd )
	{
		if ( !client_ )
			return;

		if ( !relay_client_is_connected( client_ ) ) {
			statusBar()->showMessage( "Disconnected" );
			titleLabel_->setText( "No chat selected" );
			chatStatusLabel_->setText( "Disconnected" );
			chatMetaLabel_->clear();
			composeLabel_->setText( "To: (none)" );
			resetMessageView();
			setComposerEnabled( false );
			return;
		}

		setComposerEnabled( true );

		bool shouldAutoScrollToBottom = forceScrollToEnd;
		int	 savedScrollPosition = 0;
		if ( !forceScrollToEnd && messagesScroll_->verticalScrollBar()->isVisible() ) {
			savedScrollPosition = messagesScroll_->verticalScrollBar()->value();
			int maxScroll = messagesScroll_->verticalScrollBar()->maximum();
			shouldAutoScrollToBottom = ( maxScroll > 0 && savedScrollPosition >= maxScroll - 30 );
		}

		const QString selectedBefore = currentSelectedHandle();
		const QString filter = chatSearch_->text().trimmed();

		std::vector<ChatEntry> chats;
		QString				   statusText;
		QString				   activeTitle = "(none)";
		QString				   activeHandle = QString();
		QString				   activeId = QString();
		bool				   activeE2E = false;
		std::vector<QString>   messageLines;
		std::vector<QString>   messageAuthors;

		relay_client_lock( client_ );
		statusText = fromUtf8Safe( relay_client_status( client_ ) );

		const RelayChat* active = relay_client_active_chat( client_ );
		if ( active ) {
			activeTitle = fromUtf8Safe( relay_chat_display_name( active ) );
			activeHandle = fromUtf8Safe( relay_chat_handle( active ) );
			activeId = fromUtf8Safe( relay_chat_id( active ) );
			activeE2E = relay_chat_e2e_established( active ) != 0;
		}

		for ( const RelayChat* chat = relay_client_chats( client_ ); chat; chat = relay_chat_next( chat ) ) {
			ChatEntry entry;
			entry.handle = fromUtf8Safe( relay_chat_handle( chat ) );
			entry.display = fromUtf8Safe( relay_chat_display_name( chat ) );
			entry.id = fromUtf8Safe( relay_chat_id( chat ) );
			entry.e2e = relay_chat_e2e_established( chat ) != 0;
			entry.unread = relay_chat_unread( chat );
			entry.active = ( chat == active );
			chats.push_back( std::move( entry ) );
		}

		if ( active ) {
			for ( const RelayMsg* msg = relay_chat_messages( active ); msg; msg = relay_msg_next( msg ) ) {
				messageAuthors.push_back( fromUtf8Safe( relay_msg_from( msg ) ) );
				messageLines.push_back( fromUtf8Safe( relay_msg_text( msg ) ) );
			}
		}
		relay_client_unlock( client_ );

		statusBar()->showMessage( statusText );
		titleLabel_->setText( activeTitle );
		chatStatusLabel_->setText( activeE2E ? "E2E secured" : "Not secured" );
		chatMetaLabel_->setText( activeHandle.isEmpty() ? QString()
				: activeId.isEmpty()					? "@" + activeHandle
														: QString( "@%1 · %2" ).arg( activeHandle, shortPeerId( activeId ) ) );
		composeLabel_->setText( QString( "To: %1" ).arg( activeTitle ) );

		{
			QSignalBlocker blocker( chatList_ );
			chatList_->clear();
			int rowToSelect = -1;
			for ( int i = 0; i < static_cast<int>( chats.size() ); ++i ) {
				const ChatEntry& c = chats[i];
				if ( !filter.isEmpty() && !c.display.contains( filter, Qt::CaseInsensitive ) && !c.handle.contains( filter, Qt::CaseInsensitive ) )
					continue;
				QString text = QString( "%1\n@%2" ).arg( c.display, c.handle );
				if ( !c.id.isEmpty() ) {
					text += QString( " · %1" ).arg( shortPeerId( c.id ) );
				}
				if ( c.e2e ) {
					text += " · E2E";
				}
				if ( c.unread > 0 ) {
					text += QString( " · %1 unread" ).arg( c.unread );
				}
				auto* item = new QListWidgetItem( text );
				item->setData( Qt::UserRole, c.handle );
				chatList_->addItem( item );
				if ( rowToSelect < 0 && !selectedBefore.isEmpty() && c.handle == selectedBefore )
					rowToSelect = chatList_->count() - 1;
				if ( rowToSelect < 0 && c.active )
					rowToSelect = chatList_->count() - 1;
			}
			if ( chatList_->count() == 0 ) {
				auto* item = new QListWidgetItem( filter.isEmpty() ? "No chats yet" : "No chats found" );
				item->setFlags( Qt::NoItemFlags );
				chatList_->addItem( item );
			}
			if ( rowToSelect >= 0 && rowToSelect < chatList_->count() )
				chatList_->setCurrentRow( rowToSelect );
		}

		const int  newCount = static_cast<int>( messageLines.size() );
		const int  oldCount = static_cast<int>( renderedMessageTexts_.size() );
		const bool chatChanged = ( activeId != renderedChatId_ );

		bool handledIncrementally = false;

		auto prefixMatches = [&]( int prefixLen ) {
			for ( int i = 0; i < prefixLen; ++i ) {
				if ( renderedMessageAuthors_[i] != messageAuthors[i] || renderedMessageTexts_[i] != messageLines[i] )
					return false;
			}
			return true;
		};

		if ( active && !chatChanged ) {
			if ( newCount >= oldCount && oldCount > 0 && prefixMatches( oldCount ) ) {
				for ( int i = oldCount; i < newCount; ++i ) {
					addMessageBubble( messageAuthors[i], messageLines[i], isMyMessage( messageAuthors[i] ) );
				}
				handledIncrementally = true;
			} else if ( newCount == oldCount && oldCount > 0 ) {
				int shift = -1;

				for ( int k = 1; k < oldCount; ++k ) {
					bool ok = true;
					for ( int i = 0; i < oldCount - k; ++i ) {
						if ( renderedMessageAuthors_[i + k] != messageAuthors[i] || renderedMessageTexts_[i + k] != messageLines[i] ) {
							ok = false;
							break;
						}
					}
					if ( ok ) {
						shift = k;
						break;
					}
				}

				if ( shift > 0 ) {
					for ( int i = 0; i < shift; ++i )
						removeFirstMessageBubble();

					for ( int i = oldCount - shift; i < newCount; ++i ) {
						addMessageBubble( messageAuthors[i], messageLines[i], isMyMessage( messageAuthors[i] ) );
					}
					handledIncrementally = true;
				}
			}
		}

		if ( !handledIncrementally ) {
			clearMessages();
			messagesLayout_->addStretch( 1 );

			if ( active ) {
				for ( int i = 0; i < newCount; ++i ) {
					addMessageBubble( messageAuthors[i], messageLines[i], isMyMessage( messageAuthors[i] ) );
				}
			}
		}

		renderedChatId_ = active ? activeId : QString();
		renderedMessageAuthors_ = active ? messageAuthors : std::vector<QString>();
		renderedMessageTexts_ = active ? messageLines : std::vector<QString>();

		messagesHost_->adjustSize();

		updateBubbleWidths();

		if ( shouldAutoScrollToBottom ) {
			messagesScroll_->verticalScrollBar()->setValue( messagesScroll_->verticalScrollBar()->maximum() );
		} else {
			messagesScroll_->verticalScrollBar()->setValue( savedScrollPosition );
		}
	}

	void sendMessage()
	{
		if ( !client_ )
			return;

		QString text = rtrimSpaces( input_->text() );
		if ( text.isEmpty() ) {
			input_->clear();
			return;
		}

		if ( chatList_->currentRow() < 0 ) {
			QMessageBox::information( this, "Relay", "Select a chat first." );
			return;
		}

		const QByteArray utf8 = text.toUtf8();
		relay_client_send_active( client_, utf8.constData() );
		input_->clear();
		refreshFromClient( true );
	}

	void addContact()
	{
		if ( !client_ )
			return;

		bool	ok = false;
		QString handle = QInputDialog::getText( this, "New chat", "Type recipient handle and press Enter", QLineEdit::Normal, QString(), &ok );
		if ( !ok )
			return;

		handle = rtrimSpaces( handle );
		if ( handle.isEmpty() )
			return;
		if ( handle.size() < 3 || handle.size() > MAX_NICK ) {
			QMessageBox::warning( this, "Relay", "Handle must be 3-31 characters." );
			return;
		}
		for ( const QChar ch : handle ) {
			const char c = ch.toLatin1();
			if ( !( std::isalnum( static_cast<unsigned char>( c ) ) || c == '_' || c == '-' ) ) {
				QMessageBox::warning( this, "Relay", "Handle may contain only letters, digits, '_' and '-'." );
				return;
			}
		}

		const QByteArray utf8 = handle.toUtf8();
		relay_client_open_chat( client_, utf8.constData() );
		refreshFromClient( true );
	}

private:
	RelayClient* client_ = nullptr;
	QString		 selfHandle_;
	QString		 selfId_;
	QTimer*		 timer_ = nullptr;

	QListWidget* chatList_ = nullptr;
	QLineEdit*	 chatSearch_ = nullptr;

	QScrollArea* messagesScroll_ = nullptr;
	QWidget*	 messagesHost_ = nullptr;
	QVBoxLayout* messagesLayout_ = nullptr;

	QLabel* titleLabel_ = nullptr;
	QLabel* chatStatusLabel_ = nullptr;
	QLabel* chatMetaLabel_ = nullptr;
	QLabel* appSubtitle_ = nullptr;
	QLabel* composeLabel_ = nullptr;

	QLineEdit*	 input_ = nullptr;
	QPushButton* sendBtn_ = nullptr;
	QPushButton* newChatBtn_ = nullptr;
	QPushButton* refreshBtn_ = nullptr;

	QString				 renderedChatId_;
	std::vector<QString> renderedMessageAuthors_;
	std::vector<QString> renderedMessageTexts_;
};

int main( int argc, char** argv )
{
	QApplication app( argc, argv );
	app.setStyle( "Fusion" );

	RelayConfig cfg;
	std::memset( &cfg, 0, sizeof( cfg ) );
	RelayClient* client = nullptr;

	if ( !relay_client_create( &client, &cfg ) ) {
		QMessageBox::critical( nullptr, "Relay", "Failed to init client" );
		return 1;
	}
	if ( !relay_client_connect( client, "127.0.0.1", 7777 ) ) {
		relay_client_destroy( client );
		QMessageBox::critical( nullptr, "Relay", "Failed to connect" );
		return 1;
	}

	char err[256] = { 0 };

	QString handle;
	QString nick;

	if ( relay_client_load_account( client ) ) {

		if ( !relay_client_login_saved( client, err, sizeof( err ) ) ) {
			relay_client_destroy( client );

			QMessageBox::critical( nullptr, "Relay", QString( "Saved account login failed: %1" ).arg( err[0] ? err : "unknown" ) );

			return 1;
		}

		handle = fromUtf8Safe( relay_client_handle( client ) );
		nick = fromUtf8Safe( relay_client_nick( client ) );

	} else {

		bool ok = false;

		handle = QInputDialog::getText( nullptr, "Choose your handle", "Type your unique handle and press Enter", QLineEdit::Normal, QString(), &ok );

		handle = rtrimSpaces( handle );

		if ( !ok || handle.isEmpty() ) {
			relay_client_destroy( client );
			QMessageBox::critical( nullptr, "Relay", "No handle" );
			return 1;
		}

		nick = QInputDialog::getText( nullptr, "Choose display name", "Type your visible nickname and press Enter", QLineEdit::Normal, handle, &ok );

		nick = rtrimSpaces( nick );

		if ( !ok || nick.isEmpty() ) {
			relay_client_destroy( client );
			QMessageBox::critical( nullptr, "Relay", "No display name" );
			return 1;
		}

		const QByteArray handleUtf8 = handle.toUtf8();
		const QByteArray nickUtf8 = nick.toUtf8();
		if ( !relay_client_login( client, handleUtf8.constData(), nickUtf8.constData(), err, sizeof( err ) ) ) {
			relay_client_destroy( client );
			QMessageBox::critical( nullptr, "Relay", QString( "Auth rejected: %1" ).arg( err[0] ? err : "unknown" ) );
			return 1;
		}
	}

	if ( !relay_client_start( client ) ) {
		relay_client_destroy( client );
		QMessageBox::critical( nullptr, "Relay", "Failed to start network thread" );
		return 1;
	}

	MainWindow w( client, handle, nick, fromUtf8Safe( relay_client_id( client ) ) );
	w.show();
	return app.exec();
}
